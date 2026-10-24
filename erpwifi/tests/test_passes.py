import re
import time

import pytest
from pyrad import packet
from werkzeug.security import generate_password_hash

from erpwifi.config import ConfigError, Issuer, parse_config
from erpwifi.dashboard import create_app


@pytest.fixture
def app_for(stack):
    def make(**passes):
        stack.config.dashboard.admin_password_hash = generate_password_hash("admin-pw")
        stack.config.dashboard.issuers = [Issuer("reception", generate_password_hash("desk-pw"))]
        for k, v in passes.items():
            setattr(stack.config.passes, k, v)
        app = create_app(stack.config, stack.db)
        app.testing = True
        return app.test_client()
    return make


def token(c, path):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


def sign_in(c, user, pw):
    return c.post("/login", data={"csrf": token(c, "/login"), "username": user, "password": pw})


def issue(c, hours=3, note="Jane from Acme"):
    r = c.post("/passes", data={"csrf": token(c, "/passes"), "hours": hours, "note": note},
               follow_redirects=True)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    return re.search(r'<span class="code">([A-Z2-9]{6})</span>', html).group(1), html


def test_reception_can_only_issue_passes(app_for, stack):
    c = app_for()
    r = sign_in(c, "reception", "desk-pw")
    assert r.headers["Location"] == "/passes"
    for path in ("/", "/users", "/vouchers", "/log"):
        assert c.get(path).status_code == 403
    assert c.get("/passes").status_code == 200
    assert sign_in(app_for(), "reception", "admin-pw").status_code == 200  # wrong pw: form again


def test_issue_pass_shows_code_and_sign_in_qr(app_for, stack):
    c = app_for(wifi_ssid="Trident Staff", wifi_password="pa;ss")
    sign_in(c, "reception", "desk-pw")
    code, html = issue(c, hours=4)
    assert html.count("<svg") == 2  # join-WiFi QR + sign-in QR
    assert "Jane from Acme" in html and "Trident Staff" in html
    v = stack.db.get_voucher(code)
    assert (v.kind, v.issued_by, v.profile, v.max_devices) == ("pass", "reception", "guest", 1)
    assert abs(v.expires_at - (time.time() + 4 * 3600)) < 5
    # pass list shows it as not used yet
    assert code in c.get("/passes").get_data(as_text=True)


def test_only_configured_durations(app_for, stack):
    c = app_for()
    sign_in(c, "reception", "desk-pw")
    r = c.post("/passes", data={"csrf": token(c, "/passes"), "hours": 24})
    assert r.status_code == 400


def test_pass_sign_in_and_fixed_expiry(app_for, stack):
    c = app_for()
    sign_in(c, "admin", "admin-pw")
    code, _ = issue(c)
    reply, _ = stack.router.connect(code.lower(), code.lower())
    assert reply.code == packet.AccessAccept
    assert reply["Class"][0] == f"pass|guest|{code}".encode()
    # guest profile caps a session at 1h; the pass's own 3h runs from issue
    assert reply["Session-Timeout"][0] == 3600
    # one device per pass
    assert stack.router.login(code, code, mac="11:11:11:11:11:11").code == packet.AccessReject

    # issued 2h50m ago: the remaining 10 minutes are the session cap
    stack.db._conn.execute("UPDATE vouchers SET expires_fixed = ? WHERE code = ?",
                           (time.time() + 600, code))
    stack.db._conn.commit()
    reply = stack.router.login(code, code)
    assert 590 <= reply["Session-Timeout"][0] <= 600

    stack.db._conn.execute("UPDATE vouchers SET expires_fixed = ? WHERE code = ?",
                           (time.time() - 1, code))
    stack.db._conn.commit()
    reply = stack.router.login(code, code)
    assert reply.code == packet.AccessReject
    assert reply["Reply-Message"][0] == "Temporary pass expired"


def test_unused_pass_still_expires(stack):
    [code] = stack.db.create_vouchers(1, profile="guest", valid_minutes=180, kind="pass")
    stack.db._conn.execute("UPDATE vouchers SET expires_fixed = ? WHERE code = ?",
                           (time.time() - 1, code))
    stack.db._conn.commit()
    assert stack.db.get_voucher(code).status(time.time()) == "expired"
    assert stack.router.login(code, code).code == packet.AccessReject


def test_revoke_pass_kicks_user(app_for, stack):
    c = app_for()
    sign_in(c, "reception", "desk-pw")
    code, _ = issue(c)
    stack.router.connect(code, code)
    c.post(f"/passes/{code}/revoke", data={"csrf": token(c, "/passes")})
    assert [p["User-Name"][0] for p in stack.router.disconnects] == [code]
    reply = stack.router.login(code, code)
    assert reply["Reply-Message"][0] == "Temporary pass revoked"
    assert f"<code>{code}</code>" not in c.get("/passes").get_data(as_text=True)


def test_sign_in_qr_encodes_hotspot_login_url(app_for, stack):
    """Decode the QR the visitor scans and check it logs in with the code."""
    import segno
    c = app_for(login_url="http://wifi.trident.local/login")
    sign_in(c, "admin", "admin-pw")
    code, html = issue(c)
    expected = f"http://wifi.trident.local/login?username={code}&password={code}"
    assert segno.make(expected, error="m").svg_inline(scale=5, border=2, dark="#000",
                                                      light="#fff") in html


def test_vouchers_page_hides_passes(app_for, stack):
    c = app_for()
    sign_in(c, "admin", "admin-pw")
    code, _ = issue(c)
    assert code not in c.get("/vouchers").get_data(as_text=True)


def test_pass_config_validation():
    base = {"radius": {"clients": [{"address": "1.2.3.4", "secret": "long-enough-secret"}]},
            "erpnext": {"url": "https://erp"}, "profiles": {"default": {}, "guest": {}}}
    assert parse_config(base).passes.hours == [3, 4]
    with pytest.raises(ConfigError, match="hours"):
        parse_config({**base, "passes": {"hours": [0]}})
    with pytest.raises(ConfigError, match="unknown profile"):
        parse_config({**base, "passes": {"profile": "visitors"}})
    with pytest.raises(ConfigError, match="differ"):
        parse_config({**base, "dashboard": {"issuers": [{"username": "admin", "password_hash": "x"}]}})
