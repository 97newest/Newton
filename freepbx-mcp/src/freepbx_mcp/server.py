"""FreePBX MCP server: monitoring and call tools for Hermes Agent.

Monitoring tools carry ``readOnlyHint`` so Hermes can run them freely; the
call tools do not, so a Hermes entry with ``trust: untrusted`` asks for
approval before every call or hangup.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .ami import AMIClient, AMIError, Message
from .config import CallPolicy, CallPolicyError, Settings

log = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
PLACES_CALL = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
ENDS_CALL = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)

# CLI commands the agent may run. Everything is read-only; anything that
# prints credentials (pjsip auth objects, manager users) is refused.
CLI_ALLOW = (
    "core show",
    "pjsip show",
    "pjsip list",
    "sip show",
    "iax2 show",
    "queue show",
    "bridge show",
    "cdr show",
    "module show",
    "dialplan show",
    "voicemail show",
    "confbridge list",
    "agent show",
    "channel show",
)
CLI_DENY = re.compile(r"auth|secret|password|manager|database|config", re.IGNORECASE)
CLI_CHARS = re.compile(r"[A-Za-z0-9 _./@:\-]+")

# Events worth keeping for "what happened recently" questions.
DEFAULT_EVENT_TYPES = {
    "Newchannel",
    "Hangup",
    "DialBegin",
    "DialEnd",
    "BridgeEnter",
    "ContactStatus",
    "PeerStatus",
    "Registry",
    "QueueCallerAbandon",
    "OriginateResponse",
    "FullyBooted",
    "Shutdown",
    "Reload",
    "InvalidAccountID",
    "InvalidPassword",
    "ChallengeResponseFailed",
    "FailedACL",
}

SOUND_NAME = re.compile(r"[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-]+)*")
CHANNEL_NAME = re.compile(r"[A-Za-z0-9/@._;:\-]+")
CDR_FIELDS = [
    "accountcode", "src", "dst", "dcontext", "clid", "channel", "dstchannel",
    "lastapp", "lastdata", "start", "answer", "end", "duration", "billsec",
    "disposition", "amaflags", "uniqueid", "userfield",
]


def _dump(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _pick(msg: Message, *keys: str) -> dict[str, str]:
    return {k: msg.get(k) or "" for k in keys}


def _tail_lines(path: Path, max_lines: int, max_bytes: int = 2_000_000) -> list[str]:
    size = path.stat().st_size
    with path.open("rb") as fh:
        fh.seek(max(0, size - max_bytes))
        data = fh.read().decode(errors="replace")
    lines = data.splitlines()
    if size > max_bytes and lines:
        lines = lines[1:]  # first line is probably cut in half
    return lines[-max_lines:]


def create_server(settings: Settings, ami: AMIClient | None = None) -> MCPServer:
    ami = ami or AMIClient(
        settings.ami_host,
        settings.ami_port,
        settings.ami_user,
        settings.ami_secret,
        keep_events=DEFAULT_EVENT_TYPES,
    )

    @asynccontextmanager
    async def lifespan(_server):
        # Connect up front so recent_events has history; tools reconnect later
        # if Asterisk is down or restarts.
        try:
            await ami.connect()
        except AMIError as exc:
            log.warning("%s", exc)
        yield {}
        await ami.close()

    policy = CallPolicy(settings)
    mcp = MCPServer(
        "freepbx",
        version=__version__,
        instructions=(
            "Monitor a FreePBX/Asterisk phone system and place calls. Use the "
            "read-only tools to answer questions about calls, extensions, trunks "
            "and system health. Only place calls when the user asked for one; "
            "numbers outside the configured dial policy are refused."
        ),
        lifespan=lifespan,
    )

    async def guard(coro):
        try:
            return await coro
        except (AMIError, CallPolicyError) as exc:
            return f"Error: {exc}"

    # ---------------------------------------------------------------- monitor

    @mcp.tool(annotations=READ_ONLY)
    async def system_status() -> str:
        """Asterisk version, uptime, active call count and AMI connection state."""

        async def run():
            version = await ami.command("core show version")
            uptime = await ami.command("core show uptime")
            channels = await ami.command("core show channels count")
            return _dump(
                {
                    "ami": f"{settings.ami_host}:{settings.ami_port}",
                    "banner": ami.banner,
                    "version": version,
                    "uptime": uptime,
                    "channels": channels,
                }
            )

        return await guard(run())

    @mcp.tool(annotations=READ_ONLY)
    async def list_active_calls() -> str:
        """Every channel that is up right now: who is talking to whom, and for how long."""

        async def run():
            events = await ami.list_action("CoreShowChannels")
            calls = [
                _pick(
                    e, "Channel", "CallerIDNum", "CallerIDName", "ConnectedLineNum",
                    "ConnectedLineName", "Exten", "Context", "ChannelStateDesc",
                    "Application", "Duration", "BridgeId", "Uniqueid",
                )
                for e in events
            ]
            return _dump({"count": len(calls), "channels": calls})

        return await guard(run())

    @mcp.tool(annotations=READ_ONLY)
    async def list_extensions() -> str:
        """PJSIP endpoints (extensions and trunks) with their device state and contacts.

        Falls back to chan_sip peers on systems that still use chan_sip.
        """

        async def run():
            events = await ami.list_action("PJSIPShowEndpoints")
            if events:
                items = [
                    _pick(e, "ObjectName", "DeviceState", "Contacts", "ActiveChannels")
                    for e in events
                ]
                return _dump({"driver": "pjsip", "count": len(items), "endpoints": items})
            peers = await ami.list_action("SIPpeers")
            items = [_pick(e, "ObjectName", "IPaddress", "Status") for e in peers]
            return _dump({"driver": "sip", "count": len(items), "peers": items})

        return await guard(run())

    @mcp.tool(annotations=READ_ONLY)
    async def trunk_status() -> str:
        """Outbound trunk registrations and whether each is Registered, Rejected or Unregistered."""

        async def run():
            regs = await ami.list_action("PJSIPShowRegistrationsOutbound")
            items = [
                _pick(e, "ObjectName", "ServerUri", "ClientUri", "Status", "NextReg")
                for e in regs
            ]
            contacts = await ami.list_action("PJSIPShowContacts")
            reach = [
                _pick(e, "ObjectName", "Endpoint", "Status", "RoundtripUsec", "Uri")
                for e in contacts
            ]
            return _dump({"registrations": items, "contacts": reach})

        return await guard(run())

    @mcp.tool(annotations=READ_ONLY)
    async def queue_status() -> str:
        """Call queues: callers waiting, longest hold time and available agents."""

        async def run():
            events = await ami.list_action("QueueSummary")
            items = [
                _pick(e, "Queue", "LoggedIn", "Available", "Callers", "HoldTime", "LongestHoldTime")
                for e in events
            ]
            return _dump({"queues": items})

        return await guard(run())

    @mcp.tool(annotations=READ_ONLY)
    async def recent_events(limit: int = 50, event_type: str = "") -> str:
        """Recent AMI events seen since the server connected (calls, registrations, failed logins).

        Args:
            limit: How many events to return, newest last (max 500).
            event_type: Only return this event type, e.g. "Hangup" or "InvalidPassword".
        """

        async def run():
            await ami.connect()
            if event_type and event_type not in DEFAULT_EVENT_TYPES:
                return "Error: tracked event types are " + ", ".join(sorted(DEFAULT_EVENT_TYPES))
            wanted = {event_type} if event_type else DEFAULT_EVENT_TYPES
            rows = [
                {"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.received_at)),
                 **e.as_dict()}
                for e in ami.events
                if e.get("Event") in wanted
            ]
            return _dump(rows[-max(1, min(limit, 500)):])

        return await guard(run())

    @mcp.tool(annotations=READ_ONLY)
    async def recent_calls(limit: int = 25, number: str = "") -> str:
        """Call history from the CDR CSV log.

        Args:
            limit: How many calls to return, newest last (max 200).
            number: Only calls where this number is the source or destination.
        """
        path = Path(settings.cdr_csv)
        if not path.exists():
            return f"Error: CDR CSV not found at {path} (set FREEPBX_CDR_CSV)"
        rows = []
        for line in _tail_lines(path, 5000):
            for rec in csv.reader(io.StringIO(line)):
                row = dict(zip(CDR_FIELDS, rec))
                if number and number not in (row.get("src"), row.get("dst")):
                    continue
                rows.append(
                    {k: row.get(k, "") for k in
                     ("start", "src", "dst", "clid", "disposition", "duration", "billsec", "lastapp")}
                )
        return _dump(rows[-max(1, min(limit, 200)):])

    @mcp.tool(annotations=READ_ONLY)
    async def asterisk_log(lines: int = 100, contains: str = "") -> str:
        """Tail the Asterisk full log, optionally keeping only lines containing some text.

        Args:
            lines: Lines to return (max 500).
            contains: Case-insensitive text filter, e.g. "WARNING" or "failed".
        """
        path = Path(settings.asterisk_log)
        if not path.exists():
            return f"Error: log not found at {path} (set FREEPBX_ASTERISK_LOG)"
        needle = contains.lower()
        out = [l for l in _tail_lines(path, 20000) if needle in l.lower()]
        return "\n".join(out[-max(1, min(lines, 500)):]) or "(no matching lines)"

    @mcp.tool(annotations=READ_ONLY)
    async def asterisk_cli(command: str) -> str:
        """Run a read-only Asterisk CLI command such as "pjsip show endpoint 101".

        Only "show"/"list" style commands are accepted; nothing that changes state
        or prints credentials.
        """
        cmd = " ".join(command.split())
        if (
            not CLI_CHARS.fullmatch(cmd)
            or not cmd.lower().startswith(CLI_ALLOW)
            or CLI_DENY.search(cmd)
        ):
            return "Error: command not allowed. Allowed prefixes: " + ", ".join(CLI_ALLOW)
        return await guard(ami.command(cmd))

    @mcp.tool(annotations=READ_ONLY)
    async def host_health() -> str:
        """Load, memory and disk usage of the machine this server runs on."""
        info: dict[str, Any] = {}
        try:
            info["load_avg"] = os.getloadavg()
        except OSError:
            pass
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            mem = {}
            for line in meminfo.read_text().splitlines():
                key, _, rest = line.partition(":")
                if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                    mem[key] = rest.strip()
            info["memory"] = mem
        uptime = Path("/proc/uptime")
        if uptime.exists():
            info["uptime_hours"] = round(float(uptime.read_text().split()[0]) / 3600, 1)
        disks = {}
        for mount in ("/", "/var", "/var/spool/asterisk"):
            if os.path.exists(mount):
                du = shutil.disk_usage(mount)
                disks[mount] = {
                    "used_pct": round(du.used / du.total * 100, 1),
                    "free_gb": round(du.free / 1e9, 1),
                }
        info["disk"] = disks
        return _dump(info)

    # ------------------------------------------------------------------ calls

    def outcome_text(resp: Message, outcome: Message | None, what: str) -> str:
        if outcome is None:
            return f"{what} queued ({resp.get('Message')}). No answer/failure reported yet."
        if (outcome.get("Response") or "").lower() == "success":
            return f"{what} connected (channel {outcome.get('Channel')})."
        reasons = {"0": "no such extension or number", "1": "no answer", "3": "no answer",
                   "5": "busy", "8": "congestion"}
        reason = reasons.get(outcome.get("Reason") or "", f"reason {outcome.get('Reason')}")
        return f"{what} failed: {reason}."

    @mcp.tool(annotations=PLACES_CALL)
    async def click_to_call(extension: str, number: str, wait_seconds: int = 30) -> str:
        """Ring a local extension first, then connect it to a number when answered.

        Args:
            extension: The FreePBX extension that should ring first, e.g. "101".
            number: The number or extension to connect to.
            wait_seconds: How long to wait for the extension to answer (max 60).
        """

        async def run():
            policy.check_writable()
            ext = policy.check_extension(extension)
            dest = policy.check_number(number)
            policy.take_call_slot()
            resp, outcome = await ami.originate(
                wait=max(0, min(wait_seconds, 60)),
                Channel=f"Local/{ext}@{settings.dial_context}",
                Context=settings.dial_context,
                Exten=dest,
                Priority="1",
                CallerID=f"{settings.caller_id} <{dest}>",
                Timeout=str(max(5, min(wait_seconds, 60)) * 1000),
            )
            return outcome_text(resp, outcome, f"Call {ext} -> {dest}")

        return await guard(run())

    @mcp.tool(annotations=PLACES_CALL)
    async def call_and_play(number: str, recording: str, wait_seconds: int = 45) -> str:
        """Call a number and play a recording when it answers (alerts, reminders).

        Args:
            number: The number or extension to call.
            recording: Asterisk sound name without extension, e.g. "custom/server-alert"
                (a FreePBX System Recording) or "hello-world". Join several with "&".
            wait_seconds: How long to let it ring (max 60).
        """

        async def run():
            policy.check_writable()
            dest = policy.check_number(number)
            parts = recording.split("&")
            if not all(SOUND_NAME.fullmatch(p) for p in parts):
                raise CallPolicyError(f"{recording!r} is not a valid sound name")
            policy.take_call_slot()
            resp, outcome = await ami.originate(
                wait=max(0, min(wait_seconds, 60)),
                Channel=f"Local/{dest}@{settings.dial_context}",
                Application="Playback",
                Data="&".join(parts),
                CallerID=settings.caller_id,
                Timeout=str(max(5, min(wait_seconds, 60)) * 1000),
            )
            return outcome_text(resp, outcome, f"Call to {dest}")

        return await guard(run())

    @mcp.tool(annotations=ENDS_CALL)
    async def hangup_call(channel: str) -> str:
        """Hang up one channel. Get channel names from list_active_calls.

        Args:
            channel: Full channel name, e.g. "PJSIP/101-00000012".
        """

        async def run():
            policy.check_writable()
            if not CHANNEL_NAME.fullmatch(channel):
                raise CallPolicyError(f"{channel!r} is not a valid channel name")
            await ami.action("Hangup", Channel=channel)
            return f"Hung up {channel}."

        return await guard(run())

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="FreePBX MCP server for Hermes Agent")
    parser.add_argument("--http", action="store_true", help="serve streamable HTTP instead of stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    # stdout carries the MCP protocol on stdio, so log to stderr.
    logging.basicConfig(level=os.environ.get("FREEPBX_LOG_LEVEL", "WARNING"))
    server = create_server(Settings.from_env())
    if args.http:
        server.run("streamable-http", host=args.host, port=args.port)
    else:
        server.run("stdio")


if __name__ == "__main__":
    main()
