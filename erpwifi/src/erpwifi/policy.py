"""Decides who may connect and with which limits."""

from __future__ import annotations

import hmac
import logging
import time
from dataclasses import dataclass, field

from werkzeug.security import check_password_hash, generate_password_hash

from .config import Config, Profile
from .db import Database, normalize_mac, start_of_day
from .erpnext import ERPNextClient, ERPNextUnavailable, ERPUser

log = logging.getLogger(__name__)

MB = 1024 * 1024


@dataclass
class Decision:
    accept: bool
    message: str = ""
    username: str = ""
    kind: str = ""
    profile: str = ""
    # Reply attributes (pyrad keyword names) for an Access-Accept.
    attributes: dict = field(default_factory=dict)


def _department_matches(wanted: str, actual: str) -> bool:
    # ERPNext appends the company abbreviation: "Sales - ACME".
    wanted, actual = wanted.strip().lower(), actual.strip().lower()
    return bool(actual) and (actual == wanted or actual.split(" - ")[0] == wanted)


class Policy:
    def __init__(self, config: Config, db: Database, erp: ERPNextClient):
        self.config = config
        self.db = db
        self.erp = erp

    def profile_for(self, user: ERPUser) -> Profile:
        for rule in self.config.rules:
            if rule.user and rule.user.lower() != user.user_id.lower():
                continue
            if rule.role and rule.role not in user.roles:
                continue
            if rule.department and not _department_matches(rule.department, user.department):
                continue
            return self.config.profiles[rule.profile]
        return self.config.profiles[self.config.default_profile]

    def authorize(self, username: str, password: str, mac: str, nas_ip: str) -> Decision:
        username = username.strip()
        decision = self._decide(username, password, mac)
        self.db.log_auth(decision.username or username.lower(), mac, nas_ip,
                         "accept" if decision.accept else "reject",
                         decision.message, decision.profile)
        return decision

    def _decide(self, username: str, password: str, mac: str) -> Decision:
        if not username or not password:
            return Decision(False, "Enter your username and password")
        if self.db.is_blocked(username, mac):
            return Decision(False, "This account or device is blocked")

        voucher = self.db.get_voucher(username)
        if voucher is not None:
            return self._voucher(voucher, password, mac)

        try:
            user = self.erp.authenticate(username, password)
        except ERPNextUnavailable as exc:
            log.warning("ERPNext unavailable for %s: %s", username, exc)
            return self._offline(username, password, mac)
        if user is None:
            self.db.forget_credential(username)
            return Decision(False, "Invalid username or password")
        user_id = user.user_id.lower()
        if not user.enabled:
            self.db.forget_credential(username)
            return Decision(False, "Your ERP account is disabled", username=user_id)
        required = self.config.erpnext.require_roles
        if required and not set(required) & set(user.roles):
            self.db.forget_credential(username)
            return Decision(False, "Your ERP account is not allowed to use WiFi", username=user_id)
        if self.db.is_blocked(user_id, mac):
            return Decision(False, "This account or device is blocked", username=user_id)
        profile = self.profile_for(user)
        if self.config.erpnext.offline_grace_hours:
            self.db.remember_credential(username, user_id, profile.name,
                                        generate_password_hash(password))
        return self._limits(user_id, "erp", profile, mac)

    def _offline(self, username: str, password: str, mac: str) -> Decision:
        """ERPNext is unreachable: accept a recent, identical sign-in if allowed."""
        unavailable = Decision(False, "Sign-in service unavailable, try again shortly")
        grace = self.config.erpnext.offline_grace_hours
        cached = self.db.cached_credential(username) if grace else None
        if cached is None or time.time() - cached["verified_at"] > grace * 3600:
            return unavailable
        if not check_password_hash(cached["password_hash"], password):
            return unavailable
        user_id = cached["user_id"]
        if self.db.is_blocked(user_id, mac):
            return Decision(False, "This account or device is blocked", username=user_id)
        profile = self.config.profiles.get(cached["profile"],
                                           self.config.profiles[self.config.default_profile])
        decision = self._limits(user_id, "erp", profile, mac)
        if decision.accept:
            decision.message = "Welcome (offline: ERPNext unreachable)"
        return decision

    def _voucher(self, voucher, password: str, mac: str) -> Decision:
        code = voucher.code
        label = "Temporary pass" if voucher.kind == "pass" else "Voucher"
        if not hmac.compare_digest(password.strip().upper(), code):
            return Decision(False, f"Invalid {label.lower()}", username=code)
        now = time.time()
        status = voucher.status(now)
        if status in ("revoked", "expired"):
            return Decision(False, f"{label} {status}", username=code, kind=voucher.kind)
        profile = self.config.profiles.get(voucher.profile)
        if profile is None:
            return Decision(False, f"{label} profile no longer exists", username=code)
        decision = self._limits(
            code, voucher.kind, profile, mac,
            max_devices=voucher.max_devices,
            # 0 means the profile's allowance, counted from first use
            data_bytes=voucher.data_mb * MB or None,
            usage_since=voucher.first_used_at or now,
            expires_at=voucher.expires_at or now + voucher.valid_minutes * 60,
        )
        if decision.accept and voucher.first_used_at is None:
            self.db.mark_voucher_used(code, now)
        return decision

    def _limits(self, username: str, kind: str, profile: Profile, mac: str, *,
                max_devices: int | None = None, data_bytes: int | None = None,
                usage_since: float | None = None, expires_at: float | None = None) -> Decision:
        now = time.time()
        reject = lambda msg: Decision(False, msg, username=username, kind=kind, profile=profile.name)

        max_devices = profile.max_devices if max_devices is None else max_devices
        if max_devices:
            others = [s for s in self.db.active_sessions(username)
                      if s["mac"] != normalize_mac(mac)]
            if len(others) >= max_devices:
                return reject(f"Device limit reached ({max_devices}); sign out on another device")

        since = start_of_day(now) if usage_since is None else usage_since
        used_bytes, used_seconds = self.db.usage_since(username, since)
        quota = profile.daily_data_mb * MB if data_bytes is None else data_bytes
        remaining_bytes = None
        if quota:
            remaining_bytes = quota - used_bytes
            if remaining_bytes <= 0:
                return reject("Data allowance used up")

        timeouts = []
        if profile.session_timeout:
            timeouts.append(profile.session_timeout)
        if profile.daily_time_min:
            left = profile.daily_time_min * 60 - used_seconds
            if left <= 0:
                return reject("Time allowance used up for today")
            timeouts.append(left)
        if expires_at is not None:
            left = int(expires_at - now)
            if left <= 0:
                return reject("Temporary pass expired" if kind == "pass" else "Voucher expired")
            timeouts.append(left)

        attrs: dict = {
            "Acct_Interim_Interval": self.config.radius.interim_interval,
            "Class": f"{kind}|{profile.name}|{username}".encode(),
        }
        if timeouts:
            attrs["Session_Timeout"] = max(1, int(min(timeouts)))
        if profile.idle_timeout:
            attrs["Idle_Timeout"] = profile.idle_timeout
        if self.config.radius.router_user_profile:
            attrs["Mikrotik_Group"] = self.config.radius.router_user_profile
        if profile.rate_limit:
            attrs["Mikrotik_Rate_Limit"] = profile.rate_limit
        if profile.address_list:
            attrs["Mikrotik_Address_List"] = profile.address_list
        if remaining_bytes is not None:
            attrs["Mikrotik_Total_Limit"] = remaining_bytes & 0xFFFFFFFF
            attrs["Mikrotik_Total_Limit_Gigawords"] = remaining_bytes >> 32
        return Decision(True, "Welcome", username=username, kind=kind,
                        profile=profile.name, attributes=attrs)
