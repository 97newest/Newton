"""RADIUS server the MikroTik hotspot talks to, and Disconnect-Request sender."""

from __future__ import annotations

import logging
import select
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from importlib import resources

from pyrad import packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.server import RemoteHost, Server, ServerPacketError

from .config import Config, RadiusClient
from .db import Database
from .policy import Policy

log = logging.getLogger(__name__)

TERMINATE_CAUSES = {
    1: "user-request", 2: "lost-carrier", 3: "lost-service", 4: "idle-timeout",
    5: "session-timeout", 6: "admin-reset", 7: "admin-reboot", 8: "port-error",
    9: "nas-error", 10: "nas-request", 11: "nas-reboot",
}


def load_dictionary() -> Dictionary:
    with resources.as_file(resources.files("erpwifi") / "dictionary") as path:
        return Dictionary(str(path))


def _first(pkt, name, default=None):
    try:
        return pkt[name][0]
    except KeyError:
        return default


def _octets(pkt, low, high) -> int:
    return int(_first(pkt, low, 0)) + (int(_first(pkt, high, 0)) << 32)


class RadiusServer(Server):
    def __init__(self, config: Config, db: Database, policy: Policy, dictionary=None,
                 workers: int = 16):
        hosts = {
            c.address: RemoteHost(c.address, c.secret.encode(), c.name)
            for c in config.radius.clients
        }
        super().__init__(
            authport=config.radius.auth_port, acctport=config.radius.acct_port,
            hosts=hosts, dict=dictionary or load_dictionary(), coa_enabled=False,
        )
        self.config = config
        self.db = db
        self.policy = policy
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="radius-auth")
        self._stop = threading.Event()
        # Requests being answered or recently answered, keyed by source, id and
        # authenticator, so retransmits from the router don't log in twice.
        self._inflight: dict[tuple, packet.Packet | None] = {}
        self._inflight_lock = threading.Lock()
        self.BindToAddress(config.radius.listen)

    # -- main loop ------------------------------------------------------

    def serve_forever(self):
        fds = self.authfds + self.acctfds
        self._fdmap = {fd.fileno(): fd for fd in fds}
        self._realauthfds = [fd.fileno() for fd in self.authfds]
        self._realacctfds = [fd.fileno() for fd in self.acctfds]
        log.info("RADIUS listening on %s auth=%d acct=%d", self.config.radius.listen,
                 self.authport, self.acctport)
        while not self._stop.is_set():
            ready, _, _ = select.select(fds, [], [], 0.5)
            for fd in ready:
                try:
                    self._ProcessInput(fd)
                except ServerPacketError as err:
                    log.info("Dropping packet: %s", err)
                except packet.PacketError as err:
                    log.info("Received a broken packet: %s", err)
                except Exception:
                    log.exception("Error processing packet")

    def shutdown(self):
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def close(self):
        for fd in self.authfds + self.acctfds:
            fd.close()

    # -- authentication -------------------------------------------------

    def HandleAuthPacket(self, pkt):
        key = (pkt.source, pkt.id, pkt.authenticator)
        with self._inflight_lock:
            now = time.monotonic()
            for k, (ts, _) in list(self._inflight.items()):
                if now - ts > 30:
                    del self._inflight[k]
            if key in self._inflight:
                _, reply = self._inflight[key]
                if reply is not None:
                    self.SendReplyPacket(pkt.fd, reply)
                return
            self._inflight[key] = (now, None)
        self._pool.submit(self._authenticate, pkt, key)

    def _authenticate(self, pkt, key):
        try:
            reply = self._auth_reply(pkt)
        except Exception:
            log.exception("Authentication failed with an error")
            reply = self.CreateReplyPacket(pkt)
            reply.code = packet.AccessReject
            reply.AddAttribute("Reply-Message", "Internal error")
        with self._inflight_lock:
            self._inflight[key] = (time.monotonic(), reply)
        self.SendReplyPacket(pkt.fd, reply)

    def _auth_reply(self, pkt):
        username = _first(pkt, "User-Name", "")
        mac = _first(pkt, "Calling-Station-Id", "")
        nas_ip = pkt.source[0]
        reply = self.CreateReplyPacket(pkt)

        if "User-Password" not in pkt:
            reply.code = packet.AccessReject
            msg = ("CHAP login is not supported; set login-by=http-pap on the hotspot profile"
                   if "CHAP-Password" in pkt else "No password supplied")
            reply.AddAttribute("Reply-Message", msg)
            self.db.log_auth(username.lower(), mac, nas_ip, "reject", msg)
            return reply

        password = pkt.PwDecrypt(pkt["User-Password"][0])
        decision = self.policy.authorize(username, password, mac, nas_ip)
        if not decision.accept:
            reply.code = packet.AccessReject
            reply.AddAttribute("Reply-Message", decision.message)
            log.info("Rejected %s (%s): %s", username, mac, decision.message)
            return reply

        reply.code = packet.AccessAccept
        for name, value in decision.attributes.items():
            reply.AddAttribute(name.replace("_", "-"), value)
        log.info("Accepted %s (%s) as %s/%s", decision.username, mac, decision.kind,
                 decision.profile)
        return reply

    # -- accounting -----------------------------------------------------

    def HandleAcctPacket(self, pkt):
        nas_ip = pkt.source[0]
        status = _first(pkt, "Acct-Status-Type")
        session_id = _first(pkt, "Acct-Session-Id", "")
        kind, profile, username = "", "", (_first(pkt, "User-Name", "") or "").lower()
        cls = _first(pkt, "Class")
        if cls:
            parts = bytes(cls).decode(errors="replace").split("|", 2)
            if len(parts) == 3:
                kind, profile, username = parts

        if status in ("Accounting-On", "Accounting-Off"):
            self.db.close_nas_sessions(nas_ip, "nas-reboot")
        elif status == "Start":
            self.db.acct_start(
                nas_ip=nas_ip, session_id=session_id, username=username, kind=kind,
                profile=profile, mac=_first(pkt, "Calling-Station-Id", ""),
                ip=_first(pkt, "Framed-IP-Address", ""),
            )
        elif status in ("Interim-Update", "Stop"):
            cause = _first(pkt, "Acct-Terminate-Cause", 0)
            self.db.acct_update(
                nas_ip=nas_ip, session_id=session_id, username=username, kind=kind,
                profile=profile, mac=_first(pkt, "Calling-Station-Id", ""),
                ip=_first(pkt, "Framed-IP-Address", ""),
                input_bytes=_octets(pkt, "Acct-Input-Octets", "Acct-Input-Gigawords"),
                output_bytes=_octets(pkt, "Acct-Output-Octets", "Acct-Output-Gigawords"),
                session_time=int(_first(pkt, "Acct-Session-Time", 0)),
                stop=status == "Stop",
                cause=TERMINATE_CAUSES.get(cause, str(cause)) if status == "Stop" else "",
            )
        else:
            log.info("Ignoring accounting status %r from %s", status, nas_ip)

        self.SendReplyPacket(pkt.fd, self.CreateReplyPacket(pkt))


def disconnect(client: RadiusClient, dictionary: Dictionary, *, username: str,
               session_id: str, ip: str = "", timeout: float = 3) -> bool:
    """Ask the router to end a session (RFC 5176 Disconnect-Request)."""
    radius = Client(server=client.address, secret=client.secret.encode(), dict=dictionary,
                    coaport=client.coa_port, timeout=timeout, retries=2)
    attrs = {"User_Name": username, "Acct_Session_Id": session_id}
    if ip:
        attrs["Framed_IP_Address"] = ip
    req = radius.CreateCoAPacket(code=packet.DisconnectRequest, **attrs)
    try:
        reply = radius.SendPacket(req)
    except Exception as exc:
        log.warning("Disconnect of %s on %s failed: %s", username, client.address, exc)
        return False
    return reply.code == packet.DisconnectACK
