"""A tiny fake Asterisk Manager for tests."""

from __future__ import annotations

import asyncio


def block(**fields: str) -> bytes:
    return ("".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n").encode()


class FakeAMI:
    def __init__(self, secret: str = "s3cret") -> None:
        self.secret = secret
        self.actions: list[dict[str, str]] = []
        self.server: asyncio.base_events.Server | None = None
        self.writers: list[asyncio.StreamWriter] = []
        self.originate_reason = "4"  # 4 = answered

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for w in self.writers:
            w.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    def push_event(self, **fields: str) -> None:
        for w in self.writers:
            w.write(block(**fields))

    async def _handle(self, reader, writer) -> None:
        self.writers.append(writer)
        writer.write(b"Asterisk Call Manager/9.0.0\r\n")
        msg: dict[str, str] = {}
        while line := await reader.readline():
            text = line.decode().rstrip("\r\n")
            if text:
                k, _, v = text.partition(": ")
                msg[k] = v
                continue
            self.actions.append(msg)
            writer.write(self._reply(msg))
            await writer.drain()
            msg = {}

    def _reply(self, msg: dict[str, str]) -> bytes:
        aid = msg["ActionID"]
        action = msg["Action"]
        if action == "Login":
            if msg.get("Secret") != self.secret:
                return block(Response="Error", ActionID=aid, Message="Authentication failed")
            return block(Response="Success", ActionID=aid, Message="Authentication accepted")
        if action == "Command":
            return block(
                Response="Success", ActionID=aid, Message="Command output follows",
                Output=f"ran {msg['Command']}",
            ) if msg["Command"] != "core show uptime" else (
                f"Response: Success\r\nActionID: {aid}\r\nOutput: System uptime: 1 day\r\n"
                "Output: Last reload: 2 hours\r\n\r\n"
            ).encode()
        if action == "CoreShowChannels":
            return (
                block(Response="Success", ActionID=aid, EventList="start")
                + block(Event="CoreShowChannel", ActionID=aid, Channel="PJSIP/101-00000001",
                        CallerIDNum="101", ConnectedLineNum="0712345678", Duration="00:01:02")
                + block(Event="CoreShowChannelsComplete", ActionID=aid, EventList="Complete",
                        ListItems="1")
            )
        if action == "PJSIPShowEndpoints":
            return block(Response="Error", ActionID=aid, Message="No endpoints found")
        if action == "SIPpeers":
            return (
                block(Response="Success", ActionID=aid, EventList="start")
                + block(Event="PeerEntry", ActionID=aid, ObjectName="101", Status="OK (5 ms)")
                + block(Event="PeerlistComplete", ActionID=aid, EventList="Complete")
            )
        if action == "Originate":
            return block(Response="Success", ActionID=aid, Message="Originate successfully queued") + (
                block(Event="OriginateResponse", ActionID=aid,
                      Response="Success" if self.originate_reason == "4" else "Failure",
                      Channel="PJSIP/101-00000002", Reason=self.originate_reason)
            )
        if action == "Hangup":
            return block(Response="Success", ActionID=aid, Message="Channel Hungup")
        if action == "Logoff":
            return block(Response="Goodbye", ActionID=aid)
        return block(Response="Error", ActionID=aid, Message="Invalid/unknown command")
