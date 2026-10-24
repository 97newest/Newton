"""Configuration loaded from a TOML file (see deploy/config.example.toml)."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass
class RadiusClient:
    address: str
    secret: str
    name: str = "mikrotik"
    coa_port: int = 3799


@dataclass
class RadiusConfig:
    listen: str = "0.0.0.0"
    auth_port: int = 1812
    acct_port: int = 1813
    interim_interval: int = 300
    # RouterOS hotspot user profile to put RADIUS users in (sent as
    # Mikrotik-Group). Empty leaves them in the "default" user profile.
    router_user_profile: str = ""
    clients: list[RadiusClient] = field(default_factory=list)


@dataclass
class ERPNextConfig:
    url: str
    api_key: str = ""
    api_secret: str = ""
    timeout: float = 8.0
    verify_tls: bool = True
    # Only users holding at least one of these roles may sign in; empty allows
    # every enabled ERPNext user.
    require_roles: list[str] = field(default_factory=list)
    # When ERPNext can't be reached, let people back in if they signed in with
    # the same password within this many hours. 0 refuses everyone (fail closed).
    offline_grace_hours: float = 0

    @property
    def has_api_token(self) -> bool:
        return bool(self.api_key and self.api_secret)


@dataclass
class Profile:
    name: str
    # MikroTik rate-limit string, "upload/download" from the client's view,
    # e.g. "2M/10M". Empty means no limit.
    rate_limit: str = ""
    # Longest single session in seconds; 0 means no limit.
    session_timeout: int = 0
    idle_timeout: int = 0
    # Daily allowances summed over all of a user's sessions; 0 means no limit.
    daily_data_mb: int = 0
    daily_time_min: int = 0
    # Devices online at once; 0 means no limit.
    max_devices: int = 0
    address_list: str = ""


@dataclass
class Rule:
    """Maps ERPNext users to a profile; the first matching rule wins."""
    profile: str
    role: str = ""
    department: str = ""
    user: str = ""


@dataclass
class VoucherConfig:
    default_profile: str = "guest"
    default_minutes: int = 1440
    code_length: int = 8


@dataclass
class PassConfig:
    """Temporary passes: a code (and QR code) valid for a few hours from issue."""
    profile: str = "guest"
    hours: list[int] = field(default_factory=lambda: [3, 4])
    max_devices: int = 1
    code_length: int = 6
    # Sign-in address of the hotspot, used in the sign-in QR code.
    login_url: str = "http://wifi.trident.local/login"
    # Optional join-the-WiFi QR code. Leave ssid empty to skip it.
    wifi_ssid: str = ""
    wifi_password: str = ""
    # Visitors can ask for a pass from the sign-in page; an admin or issuer
    # approves it and hands over the code. Unanswered requests lapse.
    requests_enabled: bool = True
    request_expire_minutes: int = 30
    max_pending_requests: int = 50


@dataclass
class Issuer:
    """Dashboard login that may only issue and revoke temporary passes."""
    username: str
    password_hash: str


@dataclass
class DashboardConfig:
    listen: str = "0.0.0.0"
    port: int = 8080
    admin_username: str = "admin"
    admin_password_hash: str = ""
    secret_key: str = ""
    # Networks allowed to open the dashboard, e.g. ["192.168.6.0/24"]. Empty
    # allows any address that can reach the port.
    allowed_networks: list[str] = field(default_factory=list)
    issuers: list[Issuer] = field(default_factory=list)
    # ERPNext users holding one of these roles can sign in to the dashboard
    # with their ERP account (admin: everything; issuer: passes and requests).
    erp_admin_roles: list[str] = field(default_factory=list)
    erp_issuer_roles: list[str] = field(default_factory=list)
    # Address people use for the dashboard, shown as the portal's Admin link.
    public_url: str = ""
    # Visitor request page: a separate listener that hotspot users may reach
    # before signing in (router walled garden), so the dashboard port stays closed.
    portal_port: int = 8081
    portal_url: str = ""


@dataclass
class Config:
    radius: RadiusConfig
    erpnext: ERPNextConfig
    profiles: dict[str, Profile]
    rules: list[Rule]
    default_profile: str
    vouchers: VoucherConfig
    passes: PassConfig
    dashboard: DashboardConfig
    database: str
    # IANA zone used for "today" in daily allowances, e.g. "Africa/Nairobi".
    timezone: str = ""

    def client_for(self, address: str) -> RadiusClient | None:
        for client in self.radius.clients:
            if client.address == address:
                return client
        return None


def _build(cls, data: dict, section: str):
    known = set(cls.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{section}] unknown keys: {', '.join(sorted(unknown))}")
    try:
        return cls(**data)
    except TypeError as exc:
        raise ConfigError(f"[{section}] {exc}") from exc


def parse_config(data: dict) -> Config:
    radius_data = dict(data.get("radius", {}))
    clients = [_build(RadiusClient, c, "radius.clients") for c in radius_data.pop("clients", [])]
    if not clients:
        raise ConfigError("[radius] at least one [[radius.clients]] entry is required")
    for client in clients:
        if len(client.secret) < 12:
            raise ConfigError(f"RADIUS secret for {client.address} must be at least 12 characters")
    radius = _build(RadiusConfig, radius_data, "radius")
    radius.clients = clients

    if "erpnext" not in data or "url" not in data["erpnext"]:
        raise ConfigError("[erpnext] url is required")
    erpnext = _build(ERPNextConfig, data["erpnext"], "erpnext")
    erpnext.url = erpnext.url.rstrip("/")

    profiles = {
        name: _build(Profile, {"name": name, **values}, f"profiles.{name}")
        for name, values in data.get("profiles", {}).items()
    }
    rules = [_build(Rule, r, "rules") for r in data.get("rules", [])]
    policy = data.get("policy", {})
    default_profile = policy.get("default_profile", "default")
    vouchers = _build(VoucherConfig, data.get("vouchers", {}), "vouchers")
    passes = _build(PassConfig, data.get("passes", {}), "passes")
    if not passes.hours or any(h < 1 or h > 24 for h in passes.hours):
        raise ConfigError("[passes] hours must be a list of 1-24, e.g. [3, 4]")
    dashboard_data = dict(data.get("dashboard", {}))
    issuers = [_build(Issuer, i, "dashboard.issuers") for i in dashboard_data.pop("issuers", [])]
    dashboard = _build(DashboardConfig, dashboard_data, "dashboard")
    dashboard.issuers = issuers
    if (dashboard.erp_admin_roles or dashboard.erp_issuer_roles) and not erpnext.has_api_token:
        raise ConfigError("dashboard ERP roles need erpnext.api_key and api_secret")
    if any(i.username == dashboard.admin_username for i in issuers):
        raise ConfigError("[[dashboard.issuers]] username must differ from admin_username")
    for net in dashboard.allowed_networks:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError as exc:
            raise ConfigError(f"[dashboard] allowed_networks: {exc}") from exc

    for ref, where in [(default_profile, "policy.default_profile"),
                       (vouchers.default_profile, "vouchers.default_profile"),
                       (passes.profile, "passes.profile"),
                       *[(r.profile, "rules") for r in rules]]:
        if ref not in profiles:
            raise ConfigError(f"{where} refers to unknown profile '{ref}'")
    for rule in rules:
        if not (rule.role or rule.department or rule.user):
            raise ConfigError("every [[rules]] entry needs role, department or user")
        if (rule.role or rule.department) and not erpnext.has_api_token:
            raise ConfigError("role/department rules need erpnext.api_key and api_secret")
    if erpnext.require_roles and not erpnext.has_api_token:
        raise ConfigError("erpnext.require_roles needs erpnext.api_key and api_secret")

    return Config(
        radius=radius,
        erpnext=erpnext,
        profiles=profiles,
        rules=rules,
        default_profile=default_profile,
        vouchers=vouchers,
        passes=passes,
        dashboard=dashboard,
        database=data.get("database", {}).get("path", "erpwifi.db"),
        timezone=data.get("site", {}).get("timezone", ""),
    )


def load_config(path: str | Path) -> Config:
    with open(path, "rb") as fh:
        return parse_config(tomllib.load(fh))
