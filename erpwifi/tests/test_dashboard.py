import re

import pytest
from werkzeug.security import generate_password_hash

from erpwifi.config import ConfigError, parse_config
from erpwifi.dashboard import create_app


@pytest.fixture
def client(stack):
    stack.config.dashboard.admin_password_hash = generate_password_hash("s3cret-admin")
    app = create_app(stack.config, stack.db)
    app.testing = True
    c = app.test_client()
    c.stack = stack
    return c


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def login(client):
    token = csrf(client)
    return client.post("/login", data={"csrf": token, "username": "admin",
                                       "password": "s3cret-admin"})


def test_requires_login(client):
    assert client.get("/").status_code == 302
    assert client.get("/healthz").json == {"ok": True}


def test_bad_password_and_missing_csrf(client):
    token = csrf(client)
    r = client.post("/login", data={"csrf": token, "username": "admin", "password": "x"})
    assert "Wrong username or password" in r.get_data(as_text=True)
    r = client.post("/login", data={"username": "admin", "password": "s3cret-admin"})
    assert r.status_code == 400


def test_online_page_and_kick_sends_disconnect(client):
    s = client.stack
    reply, sid = s.router.connect("sam@acme.test", "pw-sam")
    login(client)
    html = client.get("/").get_data(as_text=True)
    assert "sam@acme.test" in html and "staff" in html
    [row] = s.db.active_sessions()
    r = client.post(f"/sessions/{row['id']}/kick", data={"csrf": csrf(client, "/")},
                    follow_redirects=True)
    assert "Disconnected sam@acme.test" in r.get_data(as_text=True)
    [req] = s.router.disconnects
    assert req["Acct-Session-Id"][0] == sid
    assert req["User-Name"][0] == "sam@acme.test"


def test_block_user_kicks_and_prevents_login(client):
    s = client.stack
    s.router.connect("olu@acme.test", "pw-olu")
    login(client)
    r = client.post("/blocks", data={"csrf": csrf(client, "/"), "kind": "user",
                                     "value": "olu@acme.test", "reason": "abuse"},
                    follow_redirects=True)
    assert "disconnected 1 session" in r.get_data(as_text=True)
    assert len(s.router.disconnects) == 1
    from pyrad import packet
    assert s.router.login("olu@acme.test", "pw-olu").code == packet.AccessReject
    r = client.post("/blocks/delete", data={"csrf": csrf(client, "/users"), "kind": "user",
                                            "value": "olu@acme.test"})
    assert s.router.login("olu@acme.test", "pw-olu").code == packet.AccessAccept


def test_create_print_and_revoke_vouchers(client):
    s = client.stack
    login(client)
    r = client.post("/vouchers", data={"csrf": csrf(client, "/vouchers"), "count": "3",
                                       "profile": "guest", "minutes": "60", "devices": "2",
                                       "data_mb": "0", "note": "Visitor"},
                    follow_redirects=True)
    html = r.get_data(as_text=True)
    codes = re.findall(r"<code>([A-Z2-9]{8})</code>", html)
    assert len(codes) == 3 and "Guest WiFi voucher" in html
    from pyrad import packet
    reply, _ = s.router.connect(codes[0], codes[0])
    assert reply.code == packet.AccessAccept
    client.post(f"/vouchers/{codes[0]}/revoke", data={"csrf": csrf(client, "/vouchers")})
    assert len(s.router.disconnects) == 1
    assert "revoked" in client.get("/vouchers").get_data(as_text=True)


def test_usage_and_log_pages(client):
    s = client.stack
    reply, sid = s.router.connect("sam@acme.test", "pw-sam")
    s.router.accounting("Stop", "sam", sid, cls=reply["Class"][0], download=3 * 1024 ** 2, seconds=90)
    s.router.login("sam@acme.test", "bad")
    login(client)
    assert "3.0 MB" in client.get("/users").get_data(as_text=True)
    html = client.get("/log").get_data(as_text=True)
    assert "Invalid username or password" in html and "accept" in html


def test_open_redirect_blocked(client):
    token = csrf(client)
    r = client.post("/login?next=//evil.example", data={"csrf": token, "username": "admin",
                                                        "password": "s3cret-admin"})
    assert r.headers["Location"] == "/"


def test_config_validation():
    base = {"radius": {"clients": [{"address": "1.2.3.4", "secret": "long-enough-secret"}]},
            "erpnext": {"url": "https://erp"}, "profiles": {"default": {}, "guest": {}}}
    parse_config(base)
    with pytest.raises(ConfigError, match="at least 12"):
        parse_config({**base, "radius": {"clients": [{"address": "1.2.3.4", "secret": "short"}]}})
    with pytest.raises(ConfigError, match="unknown profile"):
        parse_config({**base, "rules": [{"user": "a@b", "profile": "nope"}]})
    with pytest.raises(ConfigError, match="api_key"):
        parse_config({**base, "rules": [{"role": "Employee", "profile": "default"}]})
    with pytest.raises(ConfigError, match="unknown keys"):
        parse_config({**base, "profiles": {"default": {"speed": 1}, "guest": {}}})
