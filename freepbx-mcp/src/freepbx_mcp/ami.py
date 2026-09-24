"""Minimal asyncio client for the Asterisk Manager Interface (AMI).

AMI is a line-based TCP protocol: every message is a block of ``Key: Value``
lines terminated by an empty line. Actions carry an ``ActionID`` that Asterisk
echoes back on the response and on any events that belong to that action
(list actions such as ``CoreShowChannels`` answer with a stream of events that
ends in an event carrying ``EventList: Complete``). Everything else is an
unsolicited event, which we keep in a ring buffer for the monitoring tools.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import time
from collections import deque
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class AMIError(Exception):
    """Raised when AMI refuses an action or the connection fails."""


@dataclass
class Message:
    """One AMI message. Keys can repeat (``Output:`` lines), so keep them all."""

    pairs: list[tuple[str, str]] = field(default_factory=list)
    received_at: float = field(default_factory=time.time)

    def get(self, key: str, default: str | None = None) -> str | None:
        key = key.lower()
        for k, v in self.pairs:
            if k.lower() == key:
                return v
        return default

    def get_all(self, key: str) -> list[str]:
        key = key.lower()
        return [v for k, v in self.pairs if k.lower() == key]

    def as_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in self.pairs:
            out[k] = f"{out[k]}\n{v}" if k in out else v
        return out

    @property
    def is_event(self) -> bool:
        return self.get("Event") is not None


@dataclass
class _Pending:
    future: asyncio.Future
    is_list: bool
    events: list[Message] = field(default_factory=list)
    response: Message | None = None


def encode_action(action: str, fields: dict[str, str | list[str]]) -> bytes:
    lines = [f"Action: {action}"]
    for key, value in fields.items():
        values = value if isinstance(value, list) else [value]
        for v in values:
            if "\r" in str(v) or "\n" in str(v):
                raise ValueError(f"AMI field {key!r} must not contain line breaks")
            lines.append(f"{key}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


class AMIClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        secret: str,
        *,
        event_buffer: int = 500,
        timeout: float = 10.0,
        keep_events: set[str] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.secret = secret
        self.timeout = timeout
        self.events: deque[Message] = deque(maxlen=event_buffer)
        # None keeps every event; Asterisk emits many per call (VarSet, Newexten).
        self.keep_events = keep_events
        self.banner: str | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._read_task: asyncio.Task | None = None
        self._pending: dict[str, _Pending] = {}
        self._ids = itertools.count(1)
        self._connect_lock = asyncio.Lock()
        # OriginateResponse events arrive after the action's response; keep
        # them keyed by ActionID so originate() can wait for the outcome.
        self._originate_waiters: dict[str, asyncio.Future] = {}

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self._writer.is_closing()

    async def connect(self) -> None:
        async with self._connect_lock:
            if self.connected:
                return
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), self.timeout
                )
                banner = await asyncio.wait_for(self._reader.readline(), self.timeout)
            except (OSError, asyncio.TimeoutError) as exc:
                await self._drop()
                raise AMIError(
                    f"cannot reach AMI at {self.host}:{self.port}: {exc}"
                ) from exc
            self.banner = banner.decode(errors="replace").strip()
            self._read_task = asyncio.create_task(self._read_loop())
            try:
                resp = await self._send(
                    "Login",
                    {"Username": self.username, "Secret": self.secret, "Events": "on"},
                    is_list=False,
                )
            except AMIError:
                await self._drop()
                raise
            if (resp.get("Response") or "").lower() != "success":
                await self._drop()
                raise AMIError(f"AMI login failed: {resp.get('Message')}")
            log.info("connected to %s (%s)", self.host, self.banner)

    async def close(self) -> None:
        if self.connected:
            try:
                await asyncio.wait_for(self._send("Logoff", {}, is_list=False), 2)
            except (AMIError, asyncio.TimeoutError):
                pass
        await self._drop()

    async def _drop(self) -> None:
        if self._read_task and self._read_task is not asyncio.current_task():
            self._read_task.cancel()
        self._read_task = None
        if self._writer:
            self._writer.close()
        self._reader = self._writer = None
        for pending in self._pending.values():
            if not pending.future.done():
                pending.future.set_exception(AMIError("AMI connection closed"))
        self._pending.clear()

    async def _read_loop(self) -> None:
        assert self._reader is not None
        current = Message()
        try:
            while True:
                raw = await self._reader.readline()
                if not raw:
                    break
                line = raw.decode(errors="replace").rstrip("\r\n")
                if line == "":
                    if current.pairs:
                        self._dispatch(current)
                    current = Message()
                    continue
                key, sep, value = line.partition(":")
                if sep:
                    current.pairs.append((key.strip(), value.strip()))
                else:
                    # Pre-13 'Response: Follows' command output is raw text.
                    current.pairs.append(("Output", line))
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - defensive
            log.exception("AMI read loop crashed")
        log.warning("AMI connection lost")
        await self._drop()

    def _dispatch(self, msg: Message) -> None:
        action_id = msg.get("ActionID")
        if msg.get("Event") == "OriginateResponse" and action_id in self._originate_waiters:
            fut = self._originate_waiters.pop(action_id)
            if not fut.done():
                fut.set_result(msg)
        pending = self._pending.get(action_id) if action_id else None
        if pending is None:
            if msg.is_event and (
                self.keep_events is None or msg.get("Event") in self.keep_events
            ):
                self.events.append(msg)
            return
        if not msg.is_event:
            pending.response = msg
            failed = (msg.get("Response") or "").lower() == "error"
            if not pending.is_list or failed or msg.get("EventList") is None:
                self._finish(action_id, pending)
            return
        if (msg.get("EventList") or "").lower() == "complete":
            self._finish(action_id, pending)
        else:
            pending.events.append(msg)

    def _finish(self, action_id: str, pending: _Pending) -> None:
        self._pending.pop(action_id, None)
        if not pending.future.done():
            pending.future.set_result(pending)

    async def _send(
        self, action: str, fields: dict[str, str | list[str]], *, is_list: bool
    ):
        if self._writer is None:
            raise AMIError("not connected to AMI")
        action_id = f"hermes-{next(self._ids)}"
        pending = _Pending(asyncio.get_running_loop().create_future(), is_list)
        self._pending[action_id] = pending
        self._writer.write(encode_action(action, {**fields, "ActionID": action_id}))
        await self._writer.drain()
        try:
            done = await asyncio.wait_for(pending.future, self.timeout)
        except asyncio.TimeoutError as exc:
            self._pending.pop(action_id, None)
            raise AMIError(f"AMI action {action} timed out") from exc
        if is_list:
            return done
        return done.response

    async def action(self, action: str, **fields: str) -> Message:
        """Run a single-response action and raise if Asterisk refuses it."""
        await self.connect()
        resp = await self._send(action, fields, is_list=False)
        if (resp.get("Response") or "").lower() == "error":
            raise AMIError(f"{action} failed: {resp.get('Message')}")
        return resp

    async def list_action(self, action: str, **fields: str) -> list[Message]:
        """Run an action that answers with an event list and return the events."""
        await self.connect()
        done = await self._send(action, fields, is_list=True)
        resp = done.response
        if resp is not None and (resp.get("Response") or "").lower() == "error":
            message = resp.get("Message") or ""
            # Asterisk answers "No endpoints found" etc. as an error.
            if "no " in message.lower() and "found" in message.lower():
                return []
            raise AMIError(f"{action} failed: {message}")
        return done.events

    async def command(self, cli: str) -> str:
        """Run an Asterisk CLI command and return its output text."""
        resp = await self.action("Command", Command=cli)
        lines = resp.get_all("Output")
        return "\n".join(l for l in lines if l != "--END COMMAND--").strip()

    async def originate(
        self, *, wait: float, **fields: str
    ) -> tuple[Message, Message | None]:
        """Queue an async Originate; optionally wait for its OriginateResponse."""
        await self.connect()
        action_id = f"hermes-{next(self._ids)}"
        fut = asyncio.get_running_loop().create_future()
        self._originate_waiters[action_id] = fut
        pending = _Pending(asyncio.get_running_loop().create_future(), False)
        self._pending[action_id] = pending
        assert self._writer is not None
        self._writer.write(
            encode_action("Originate", {**fields, "Async": "true", "ActionID": action_id})
        )
        await self._writer.drain()
        try:
            done = await asyncio.wait_for(pending.future, self.timeout)
        except asyncio.TimeoutError as exc:
            self._pending.pop(action_id, None)
            self._originate_waiters.pop(action_id, None)
            raise AMIError("Originate timed out") from exc
        resp = done.response
        if (resp.get("Response") or "").lower() == "error":
            self._originate_waiters.pop(action_id, None)
            raise AMIError(f"Originate failed: {resp.get('Message')}")
        outcome = None
        if wait > 0:
            try:
                outcome = await asyncio.wait_for(fut, wait)
            except asyncio.TimeoutError:
                pass
        self._originate_waiters.pop(action_id, None)
        return resp, outcome
