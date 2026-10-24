"""Checks credentials against ERPNext / Frappe and looks up roles."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

import requests

from .config import ERPNextConfig

log = logging.getLogger(__name__)


class ERPNextUnavailable(Exception):
    """ERPNext could not be reached or answered unexpectedly."""


@dataclass
class ERPUser:
    user_id: str
    full_name: str = ""
    enabled: bool = True
    roles: list[str] = field(default_factory=list)
    department: str = ""


class ERPNextClient:
    def __init__(self, config: ERPNextConfig):
        self.config = config

    def _token_headers(self) -> dict[str, str]:
        return {"Authorization": f"token {self.config.api_key}:{self.config.api_secret}"}

    def authenticate(self, username: str, password: str) -> ERPUser | None:
        """Return the user if ERPNext accepts the password, None if it refuses."""
        url = self.config.url
        with requests.Session() as session:
            try:
                resp = session.post(
                    f"{url}/api/method/login",
                    data={"usr": username, "pwd": password},
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                )
            except requests.RequestException as exc:
                raise ERPNextUnavailable(f"login request failed: {exc}") from exc
            if resp.status_code in (401, 403):
                return None
            if resp.status_code == 429:
                raise ERPNextUnavailable("ERPNext is rate limiting logins")
            if resp.status_code != 200:
                raise ERPNextUnavailable(f"login returned HTTP {resp.status_code}")

            user_id = unquote(session.cookies.get("user_id") or "") or username
            try:
                full_name = resp.json().get("full_name", "")
            except ValueError:
                full_name = ""
            try:
                session.get(f"{url}/api/method/logout", timeout=self.config.timeout,
                            verify=self.config.verify_tls)
            except requests.RequestException:
                log.debug("ERPNext logout failed", exc_info=True)

        user = ERPUser(user_id=user_id, full_name=full_name)
        if self.config.has_api_token:
            self._load_details(user)
        return user

    def _get(self, path: str, params: dict | None = None) -> dict:
        try:
            resp = requests.get(
                f"{self.config.url}{path}",
                params=params,
                headers=self._token_headers(),
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
        except requests.RequestException as exc:
            raise ERPNextUnavailable(f"lookup failed: {exc}") from exc
        if resp.status_code != 200:
            raise ERPNextUnavailable(f"{path} returned HTTP {resp.status_code}")
        return resp.json()

    def _load_details(self, user: ERPUser) -> None:
        doc = self._get(f"/api/resource/User/{quote(user.user_id, safe='')}").get("data", {})
        user.enabled = bool(doc.get("enabled", 1))
        user.full_name = doc.get("full_name") or user.full_name
        user.roles = [r["role"] for r in doc.get("roles", []) if r.get("role")]
        employees = self._get("/api/resource/Employee", params={
            "filters": json.dumps([["user_id", "=", user.user_id]]),
            "fields": json.dumps(["name", "department", "status"]),
            "limit_page_length": 1,
        }).get("data", [])
        if employees:
            user.department = employees[0].get("department") or ""
            if employees[0].get("status") not in (None, "", "Active"):
                user.enabled = False
