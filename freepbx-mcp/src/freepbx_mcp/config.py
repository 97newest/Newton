"""Settings, read from environment variables (see deploy/freepbx-mcp.env.example)."""

from __future__ import annotations

import os
import re
import time
from collections import deque
from dataclasses import dataclass, field


def load_env_file(path: str) -> None:
    """Fill unset variables from a KEY=value file, so secrets can live on the PBX."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _regex(name: str, default: str) -> re.Pattern[str]:
    return re.compile(os.environ.get(name) or default)


# Internal FreePBX extensions only. Widen FREEPBX_DIAL_ALLOW deliberately.
DEFAULT_DIAL_ALLOW = r"^[0-9]{2,6}$"
# International and premium prefixes are the usual toll-fraud targets.
DEFAULT_DIAL_DENY = r"^(\+|00|011|900|1900)"


@dataclass
class Settings:
    ami_host: str
    ami_port: int
    ami_user: str
    ami_secret: str
    dial_allow: re.Pattern[str]
    dial_deny: re.Pattern[str]
    extension_pattern: re.Pattern[str]
    caller_id: str
    dial_context: str
    max_calls_per_hour: int
    read_only: bool
    asterisk_log: str
    cdr_csv: str

    @classmethod
    def from_env(cls) -> "Settings":
        load_env_file(os.environ.get("FREEPBX_MCP_ENV_FILE", "/etc/freepbx-mcp.env"))
        secret = os.environ.get("FREEPBX_AMI_SECRET", "")
        if not secret:
            raise SystemExit("FREEPBX_AMI_SECRET is not set")
        return cls(
            ami_host=os.environ.get("FREEPBX_AMI_HOST", "127.0.0.1"),
            ami_port=int(os.environ.get("FREEPBX_AMI_PORT", "5038")),
            ami_user=os.environ.get("FREEPBX_AMI_USER", "hermes"),
            ami_secret=secret,
            dial_allow=_regex("FREEPBX_DIAL_ALLOW", DEFAULT_DIAL_ALLOW),
            dial_deny=_regex("FREEPBX_DIAL_DENY", DEFAULT_DIAL_DENY),
            extension_pattern=_regex("FREEPBX_EXTENSION_PATTERN", r"^[0-9]{2,6}$"),
            caller_id=os.environ.get("FREEPBX_CALLER_ID", "Hermes"),
            dial_context=os.environ.get("FREEPBX_DIAL_CONTEXT", "from-internal"),
            max_calls_per_hour=int(os.environ.get("FREEPBX_MAX_CALLS_PER_HOUR", "20")),
            read_only=_bool("FREEPBX_READ_ONLY", False),
            asterisk_log=os.environ.get("FREEPBX_ASTERISK_LOG", "/var/log/asterisk/full"),
            cdr_csv=os.environ.get(
                "FREEPBX_CDR_CSV", "/var/log/asterisk/cdr-csv/Master.csv"
            ),
        )


class CallPolicyError(Exception):
    """A requested call breaks the configured dialing policy."""


@dataclass
class CallPolicy:
    settings: Settings
    _recent: deque[float] = field(default_factory=deque)

    def check_number(self, number: str) -> str:
        number = number.strip().replace(" ", "").replace("-", "")
        if not re.fullmatch(r"\+?[0-9*#]{1,20}", number):
            raise CallPolicyError(f"{number!r} is not a dialable number")
        if self.settings.dial_deny.search(number):
            raise CallPolicyError(f"{number} matches FREEPBX_DIAL_DENY")
        if not self.settings.dial_allow.search(number):
            raise CallPolicyError(
                f"{number} is not allowed by FREEPBX_DIAL_ALLOW "
                f"({self.settings.dial_allow.pattern})"
            )
        return number

    def check_extension(self, extension: str) -> str:
        extension = extension.strip()
        if not self.settings.extension_pattern.fullmatch(extension):
            raise CallPolicyError(f"{extension!r} is not a valid extension")
        return extension

    def check_writable(self) -> None:
        if self.settings.read_only:
            raise CallPolicyError("this server runs with FREEPBX_READ_ONLY=1")

    def take_call_slot(self) -> None:
        now = time.monotonic()
        while self._recent and now - self._recent[0] > 3600:
            self._recent.popleft()
        if len(self._recent) >= self.settings.max_calls_per_hour:
            raise CallPolicyError(
                f"call limit reached ({self.settings.max_calls_per_hour} per hour)"
            )
        self._recent.append(now)
