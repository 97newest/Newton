import re
import time

import pytest
from pyrad import packet
from werkzeug.security import generate_password_hash

from erpwifi.config import Issuer
from erpwifi.dashboard import create_app
from erpwifi.erpnext import ERPNextClient
from erpwifi.portal import create_portal_app


def token(c, path):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


@pytest.fixture
def apps(stack):
    stack.config.dashboard.admin_password_hash = generate_password_hash("admin-pw")
    stack.config.dashboard.issuers = [Issuer("reception", generate_password_hash("desk-pw"))]
    stack.config.dashboard.erp_admin_roles = ["System Manager"]
    stack.config.dashboard.erp_issuer_roles = ["Receptionist"]
    stack.config.dashboard.portal_url = "http://172.31.250.2:8081/request"
    stack.config.dashboard.public_url = "http://wifi-admin.trident.local"
    stack.erp.add_user("rose@acme.test", "pw-rose", roles=["Employee", "Receptionist"])
    dash = create_app(stack.config, stack.db, erp=ERPNextClient(stack.config.erpnext))
    portal = create_portal_app(stack.config, stack.db)
    dash.testing = portal.testing = True
    return dash.test_client(), portal.test_client()


def visitor_asks(portal, name="Jane Visitor", visiting="Sam in Sales", ip="192.168.81.150"):
    env = {"REMOTE_ADDR": ip}
    t = token(portal, "/request?mac=AA:BB:CC:DD:EE:01")
    r = portal.post("/request", data={"csrf": t, "name": name, "organisation": "Acme Pipes",
                                      "visiting": visiting, "mac": "AA:BB:CC:DD:EE:01"},
                    environ_base=env)
    assert r.status_code == 302, r.get_data(as_text=True)
    return r.headers["Location"]


def staff_sign_in(dash, user, pw):
    t = token(dash, "/login")
    return dash.post("/login", data={"csrf": t, "username": user, "password": pw})


def test_full_visitor_flow(apps, stack):
    dash, portal = apps
    status_url = visitor_asks(portal)
    page = portal.get(status_url).get_data(as_text=True)
    assert "Waiting for approval" in page and 'http-equiv="refresh"' in page

    staff_sign_in(dash, "reception", "desk-pw")
    html = dash.get("/requests").get_data(as_text=True)
    assert "Jane Visitor" in html and "Sam in Sales" in html and "AA:BB:CC:DD:EE:01" in html
    assert '<span class="tag active">1</span>' in dash.get("/passes").get_data(as_text=True)

    pk = re.search(r"/requests/(\d+)/approve", html).group(1)
    r = dash.post(f"/requests/{pk}/approve", data={"csrf": token(dash, "/requests"), "hours": 4},
                  follow_redirects=True)
    shown = r.get_data(as_text=True)
    code = re.search(r'<span class="code">([A-Z2-9]{6})</span>', shown).group(1)
    assert "<svg" in shown and "Jane Visitor (Acme Pipes), visiting Sam in Sales" in shown

    # The visitor's own page says approved but never shows the code
    page = portal.get(status_url).get_data(as_text=True)
    assert "Approved" in page and "reception" in page and code not in page

    v = stack.db.get_voucher(code)
    assert v.kind == "pass" and v.issued_by == "reception"
    assert abs(v.expires_at - (time.time() + 4 * 3600)) < 5
    assert stack.router.login(code, code).code == packet.AccessAccept


def test_decline_and_double_answer(apps, stack):
    dash, portal = apps
    status_url = visitor_asks(portal)
    staff_sign_in(dash, "admin", "admin-pw")
    pk = re.search(r"/requests/(\d+)/approve", dash.get("/requests").get_data(as_text=True)).group(1)
    dash.post(f"/requests/{pk}/decline", data={"csrf": token(dash, "/requests")})
    assert "declined" in portal.get(status_url).get_data(as_text=True)
    # approving after a decline issues nothing usable
    r = dash.post(f"/requests/{pk}/approve", data={"csrf": token(dash, "/requests"), "hours": 3},
                  follow_redirects=True)
    assert "already answered" in r.get_data(as_text=True)
    assert all(v.status(time.time()) == "revoked" for v in stack.db.list_vouchers(kind="pass"))


def test_requests_expire(apps, stack):
    dash, portal = apps
    status_url = visitor_asks(portal)
    stack.db._conn.execute("UPDATE access_requests SET created_at = created_at - 3600")
    stack.db._conn.commit()
    assert "expired" in portal.get(status_url).get_data(as_text=True)


def test_request_validation_and_rate_limit(apps, stack):
    _, portal = apps
    t = token(portal, "/request")
    r = portal.post("/request", data={"csrf": t, "name": "", "visiting": ""})
    assert "Please enter your name" in r.get_data(as_text=True)
    assert portal.post("/request", data={"name": "x", "visiting": "y"}).status_code == 400  # no CSRF
    for i in range(3):
        visitor_asks(portal, name=f"V{i}", ip="192.168.81.9")
    t = token(portal, "/request")
    r = portal.post("/request", data={"csrf": t, "name": "V4", "visiting": "y"},
                    environ_base={"REMOTE_ADDR": "192.168.81.9"})
    assert "already has requests waiting" in r.get_data(as_text=True)
    visitor_asks(portal, ip="192.168.81.10")  # other devices still can


def test_portal_has_no_admin_functions(apps):
    _, portal = apps
    for path in ("/", "/requests", "/passes", "/login", "/vouchers"):
        r = portal.get(path)
        assert r.status_code in (302, 404)
        if r.status_code == 302:
            assert r.headers["Location"].startswith("/request")


def test_erp_receptionist_and_admin_sign_in(apps, stack):
    dash, _ = apps
    r = staff_sign_in(dash, "rose@acme.test", "pw-rose")
    assert r.headers["Location"] == "/passes"
    assert dash.get("/").status_code == 403
    assert "rose@acme.test" in dash.get("/requests").get_data(as_text=True)

    dash2 = create_app(stack.config, stack.db, erp=ERPNextClient(stack.config.erpnext)).test_client()
    assert staff_sign_in(dash2, "jane", "pw-jane").headers["Location"] == "/"  # System Manager

    dash3 = create_app(stack.config, stack.db, erp=ERPNextClient(stack.config.erpnext)).test_client()
    r = staff_sign_in(dash3, "sam@acme.test", "pw-sam")  # plain employee
    assert r.status_code == 200 and "Wrong username or password" in r.get_data(as_text=True)


def test_local_admin_works_when_erpnext_down(apps, stack):
    dash, _ = apps
    stack.erp.down = True
    assert staff_sign_in(dash, "admin", "admin-pw").headers["Location"] == "/"


def test_sign_in_page_links_filled_in(apps):
    dash, _ = apps
    page = dash.get("/hotspot/login.html").get_data(as_text=True)
    assert 'href="http://172.31.250.2:8081/request?mac=$(mac-esc)"' in page
    assert 'href="http://wifi-admin.trident.local">Admin' in page
    assert "Staff: sign in with ERP" in page and "Visitor: temporary access" in page
    assert "__" not in page
