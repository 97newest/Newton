"""Minimal stand-in for the ERPNext/Frappe endpoints erpwifi uses."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

API_KEY, API_SECRET = "apikey123", "apisecret456"


class FakeERPNext:
    def __init__(self):
        # user_id -> record
        self.users: dict[str, dict] = {}
        self.down = False
        self.logins = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, headers=()):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if fake.down:
                    return self._send(502, {"message": "Bad gateway"})
                if urlparse(self.path).path != "/api/method/login":
                    return self._send(404, {})
                length = int(self.headers.get("Content-Length", 0))
                form = parse_qs(self.rfile.read(length).decode())
                usr, pwd = form.get("usr", [""])[0], form.get("pwd", [""])[0]
                fake.logins += 1
                user = fake.find(usr)
                if user is None or user["password"] != pwd:
                    return self._send(401, {"message": "Invalid login credentials"})
                if not user["enabled"]:
                    return self._send(401, {"message": "User disabled or missing"})
                self._send(200, {"message": "Logged In", "home_page": "/app",
                                 "full_name": user["full_name"]},
                           headers=[("Set-Cookie", "sid=abc; Path=/"),
                                    ("Set-Cookie", f"user_id={quote(user['user_id'])}; Path=/")])

            def do_GET(self):
                url = urlparse(self.path)
                if url.path == "/api/method/logout":
                    return self._send(200, {})
                if self.headers.get("Authorization") != f"token {API_KEY}:{API_SECRET}":
                    return self._send(403, {"exc_type": "PermissionError"})
                if url.path.startswith("/api/resource/User/"):
                    user = fake.users.get(unquote(url.path.rsplit("/", 1)[1]))
                    if user is None:
                        return self._send(404, {})
                    return self._send(200, {"data": {
                        "name": user["user_id"], "enabled": int(user["enabled"]),
                        "full_name": user["full_name"],
                        "roles": [{"role": r, "doctype": "Has Role"} for r in user["roles"]]}})
                if url.path == "/api/resource/Employee":
                    filters = json.loads(parse_qs(url.query)["filters"][0])
                    user = fake.users.get(filters[0][2])
                    data = []
                    if user and user.get("department") is not None:
                        data = [{"name": "HR-EMP-0001", "department": user["department"],
                                 "status": user.get("employee_status", "Active")}]
                    return self._send(200, {"data": data})
                self._send(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def add_user(self, user_id, password, *, username=None, full_name="Test User", roles=(),
                 department=None, enabled=True, employee_status="Active"):
        self.users[user_id] = dict(user_id=user_id, username=username or user_id.split("@")[0],
                                   password=password, full_name=full_name, roles=list(roles),
                                   department=department, enabled=enabled,
                                   employee_status=employee_status)

    def find(self, usr):
        for user in self.users.values():
            if usr.lower() in (user["user_id"].lower(), user["username"].lower()):
                return user
        return None

    def close(self):
        self.server.shutdown()
