"""Simulates a MikroTik hotspot talking RADIUS: PAP logins, accounting and a
Disconnect-Request (CoA port) listener."""

from __future__ import annotations

import socket
import threading

from pyrad import packet
from pyrad.client import Client


class FakeRouter:
    def __init__(self, dictionary, server_port_auth, server_port_acct, secret: bytes):
        self.dict = dictionary
        self.secret = secret
        self.client = Client(server="127.0.0.1", authport=server_port_auth,
                             acctport=server_port_acct, secret=secret, dict=dictionary,
                             timeout=5, retries=1)
        self.disconnects: list[packet.Packet] = []
        self.coa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.coa_sock.bind(("127.0.0.1", 0))
        self.coa_port = self.coa_sock.getsockname()[1]
        self._session = 0
        threading.Thread(target=self._coa_loop, daemon=True).start()

    def _coa_loop(self):
        while True:
            try:
                data, addr = self.coa_sock.recvfrom(4096)
            except OSError:
                return
            req = packet.CoAPacket(packet=data, secret=self.secret, dict=self.dict)
            if not req.VerifyCoARequest():
                continue
            self.disconnects.append(req)
            reply = req.CreateReply()
            reply.code = packet.DisconnectACK
            self.coa_sock.sendto(reply.ReplyPacket(), addr)

    def login(self, username, password, mac="AA:BB:CC:00:00:01", chap=False):
        req = self.client.CreateAuthPacket(code=packet.AccessRequest, User_Name=username)
        req["NAS-Identifier"] = "0. Firewall"
        req["Calling-Station-Id"] = mac
        req["Called-Station-Id"] = "hotspot1"
        req["NAS-Port-Type"] = 19
        req["Service-Type"] = 1
        if chap:
            req["CHAP-Password"] = b"\x01" + b"0" * 16
            req["CHAP-Challenge"] = b"1" * 16
        else:
            req["User-Password"] = req.PwCrypt(password)
        req.add_message_authenticator()
        return self.client.SendPacket(req)

    def accounting(self, status, username, session_id, *, mac="AA:BB:CC:00:00:01",
                   ip="10.5.50.10", cls=None, upload=0, download=0, seconds=0, cause=None):
        req = self.client.CreateAcctPacket(User_Name=username)
        req["Acct-Status-Type"] = status
        req["Acct-Session-Id"] = session_id
        req["Calling-Station-Id"] = mac
        req["Framed-IP-Address"] = ip
        if cls is not None:
            req["Class"] = cls
        if status in ("Interim-Update", "Stop"):
            req["Acct-Input-Octets"] = upload & 0xFFFFFFFF
            req["Acct-Input-Gigawords"] = upload >> 32
            req["Acct-Output-Octets"] = download & 0xFFFFFFFF
            req["Acct-Output-Gigawords"] = download >> 32
            req["Acct-Session-Time"] = seconds
        if cause is not None:
            req["Acct-Terminate-Cause"] = cause
        return self.client.SendPacket(req)

    def connect(self, username, password, mac="AA:BB:CC:00:00:01"):
        """Log in and send Accounting-Start like the hotspot does; returns (reply, session_id)."""
        reply = self.login(username, password, mac)
        if reply.code != packet.AccessAccept:
            return reply, None
        self._session += 1
        sid = f"8100{self._session:04x}"
        self.accounting("Start", username, sid, mac=mac, cls=reply["Class"][0])
        return reply, sid

    def close(self):
        self.coa_sock.close()
