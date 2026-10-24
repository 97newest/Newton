import time

from pyrad import packet

GB = 1024 ** 3
MB = 1024 ** 2


def attr(reply, name, default=None):
    return reply[name][0] if name in reply else default


def test_erp_user_gets_rule_profile(stack):
    reply = stack.router.login("sam@acme.test", "pw-sam")
    assert reply.code == packet.AccessAccept
    assert attr(reply, "Mikrotik-Rate-Limit") == "10M/20M"
    assert attr(reply, "Class") == b"erp|staff|sam@acme.test"
    assert attr(reply, "Acct-Interim-Interval") == 60
    assert "Session-Timeout" not in reply  # staff has no time limit


def test_login_by_short_username_maps_to_erp_user_id(stack):
    reply = stack.router.login("jane", "pw-jane")
    assert reply.code == packet.AccessAccept
    assert attr(reply, "Class") == b"erp|admin|jane@acme.test"
    assert "Mikrotik-Rate-Limit" not in reply


def test_default_profile_limits(stack):
    reply = stack.router.login("olu@acme.test", "pw-olu")
    assert reply.code == packet.AccessAccept
    assert attr(reply, "Mikrotik-Rate-Limit") == "2M/5M"
    assert attr(reply, "Session-Timeout") == 28800
    assert attr(reply, "Mikrotik-Total-Limit") == 1024 * MB
    assert attr(reply, "Mikrotik-Total-Limit-Gigawords") == 0


def test_wrong_password_rejected_with_message(stack):
    reply = stack.router.login("sam@acme.test", "nope")
    assert reply.code == packet.AccessReject
    assert attr(reply, "Reply-Message") == "Invalid username or password"
    log = stack.db.recent_auth()[0]
    assert (log["username"], log["result"]) == ("sam@acme.test", "reject")


def test_disabled_and_departed_and_roleless_users_rejected(stack):
    assert stack.router.login("gone@acme.test", "pw-gone").code == packet.AccessReject
    reply = stack.router.login("left@acme.test", "pw-left")
    assert reply.code == packet.AccessReject
    assert attr(reply, "Reply-Message") == "Your ERP account is disabled"
    reply = stack.router.login("cust@acme.test", "pw-cust")
    assert reply.code == packet.AccessReject
    assert "not allowed" in attr(reply, "Reply-Message")


def test_erpnext_down_rejects_politely(stack):
    stack.erp.down = True
    reply = stack.router.login("sam@acme.test", "pw-sam")
    assert reply.code == packet.AccessReject
    assert "unavailable" in attr(reply, "Reply-Message")


def test_chap_is_refused_with_hint(stack):
    reply = stack.router.login("sam@acme.test", "pw-sam", chap=True)
    assert reply.code == packet.AccessReject
    assert "http-pap" in attr(reply, "Reply-Message")


def test_wrong_shared_secret_gets_no_answer(stack):
    from fake_router import FakeRouter
    import pytest
    from pyrad.client import Timeout

    rogue = FakeRouter(stack.dictionary, stack.config.radius.auth_port,
                       stack.config.radius.acct_port, b"not-the-right-secret")
    rogue.client.timeout = 1
    rogue.client.retries = 1
    with pytest.raises(Timeout):
        rogue.login("sam@acme.test", "pw-sam")
    rogue.close()


def test_accounting_tracks_session_and_usage(stack):
    r = stack.router
    reply, sid = r.connect("sam@acme.test", "pw-sam")
    cls = reply["Class"][0]
    [s] = stack.db.active_sessions()
    assert (s["username"], s["kind"], s["profile"], s["mac"]) == \
        ("sam@acme.test", "erp", "staff", "AA:BB:CC:00:00:01")

    r.accounting("Interim-Update", "sam@acme.test", sid, cls=cls,
                 upload=5 * MB, download=5 * GB, seconds=600)
    [s] = stack.db.active_sessions()
    assert s["output_bytes"] == 5 * GB and s["session_time"] == 600

    r.accounting("Stop", "sam@acme.test", sid, cls=cls, upload=6 * MB, download=6 * GB,
                 seconds=900, cause=1)
    assert stack.db.active_sessions() == []
    used, seconds = stack.db.usage_since("sam@acme.test", 0)
    assert used == 6 * MB + 6 * GB and seconds == 900


def test_daily_data_quota_counts_down_and_blocks(stack):
    r = stack.router
    reply, sid = r.connect("olu@acme.test", "pw-olu")
    r.accounting("Stop", "olu", sid, cls=reply["Class"][0], download=1000 * MB, seconds=60)
    reply = r.login("olu@acme.test", "pw-olu")
    assert reply.code == packet.AccessAccept
    assert attr(reply, "Mikrotik-Total-Limit") == 24 * MB

    reply, sid = r.connect("olu@acme.test", "pw-olu")
    r.accounting("Stop", "olu", sid, cls=reply["Class"][0], download=30 * MB, seconds=60)
    reply = r.login("olu@acme.test", "pw-olu")
    assert reply.code == packet.AccessReject
    assert attr(reply, "Reply-Message") == "Data allowance used up"


def test_device_limit(stack):
    r = stack.router
    assert r.connect("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:01")[1]
    assert r.connect("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:02")[1]
    # Re-login from a device already online is fine
    assert r.login("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:02").code == packet.AccessAccept
    reply = r.login("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:03")
    assert reply.code == packet.AccessReject
    assert "Device limit" in attr(reply, "Reply-Message")


def test_stale_sessions_do_not_count(stack):
    r = stack.router
    reply, sid = r.connect("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:01")
    r.connect("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:02")
    stack.db._conn.execute("UPDATE sessions SET updated_at = updated_at - 1000")
    stack.db._conn.commit()
    assert r.login("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:03").code == packet.AccessAccept


def test_blocked_user_and_mac(stack):
    stack.db.add_block("user", "Sam@acme.test")
    reply = stack.router.login("sam@acme.test", "pw-sam")
    assert reply.code == packet.AccessReject and "blocked" in attr(reply, "Reply-Message")
    # Block applies to the ERP user id even when signing in with the short username
    stack.db.add_block("user", "jane@acme.test")
    assert stack.router.login("jane", "pw-jane").code == packet.AccessReject
    stack.db.add_block("mac", "aa-bb-cc-00-00-09")
    assert stack.router.login("olu@acme.test", "pw-olu",
                              mac="AA:BB:CC:00:00:09").code == packet.AccessReject
    assert stack.router.login("olu@acme.test", "pw-olu").code == packet.AccessAccept


def test_voucher_lifecycle(stack):
    [code] = stack.db.create_vouchers(1, profile="guest", valid_minutes=30, max_devices=1)
    r = stack.router
    assert r.login(code, "WRONG").code == packet.AccessReject
    reply, sid = r.connect(code.lower(), code.lower())
    assert reply.code == packet.AccessAccept
    assert attr(reply, "Mikrotik-Rate-Limit") == "1M/2M"
    # 30 minute validity is shorter than the guest profile's 1 hour session cap
    assert 1790 <= attr(reply, "Session-Timeout") <= 1800
    assert attr(reply, "Class") == f"voucher|guest|{code}".encode()
    assert stack.db.get_voucher(code).status(time.time()) == "active"

    # one device only
    assert r.login(code, code, mac="11:22:33:44:55:66").code == packet.AccessReject

    stack.db.revoke_voucher(code)
    reply = r.login(code, code)
    assert reply.code == packet.AccessReject and attr(reply, "Reply-Message") == "Voucher revoked"


def test_voucher_expiry_and_data_cap(stack):
    [code] = stack.db.create_vouchers(1, profile="guest", valid_minutes=10, data_mb=100)
    reply, sid = stack.router.connect(code, code)
    assert attr(reply, "Mikrotik-Total-Limit") == 100 * MB
    stack.router.accounting("Stop", code, sid, cls=reply["Class"][0], download=100 * MB, seconds=5)
    reply = stack.router.login(code, code)
    assert attr(reply, "Reply-Message") == "Data allowance used up"

    [code2] = stack.db.create_vouchers(1, profile="guest", valid_minutes=10)
    stack.db.mark_voucher_used(code2, time.time() - 601)
    reply = stack.router.login(code2, code2)
    assert reply.code == packet.AccessReject and attr(reply, "Reply-Message") == "Voucher expired"


def test_large_quota_uses_gigawords(stack):
    stack.config.profiles["default"].daily_data_mb = 10 * 1024
    reply = stack.router.login("olu@acme.test", "pw-olu")
    total = attr(reply, "Mikrotik-Total-Limit") + (attr(reply, "Mikrotik-Total-Limit-Gigawords") << 32)
    assert total == 10 * GB


def test_accounting_on_closes_router_sessions(stack):
    stack.router.connect("sam@acme.test", "pw-sam")
    assert len(stack.db.active_sessions()) == 1
    stack.router.accounting("Accounting-On", "", "")
    assert stack.db.active_sessions() == []


def test_retransmit_does_not_hit_erp_twice(stack):
    import socket
    from pyrad import packet as p

    r = stack.router
    req = r.client.CreateAuthPacket(code=p.AccessRequest, User_Name="sam@acme.test")
    req["User-Password"] = req.PwCrypt("pw-sam")
    req["Calling-Station-Id"] = "AA:BB:CC:00:00:01"
    req.add_message_authenticator()
    raw = req.RequestPacket()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    before = stack.erp.logins
    for _ in range(3):
        sock.sendto(raw, ("127.0.0.1", stack.config.radius.auth_port))
    replies = []
    try:
        while len(replies) < 3:
            replies.append(req.CreateReply(packet=sock.recv(4096)))
            sock.settimeout(1)
    except socket.timeout:
        pass
    sock.close()
    assert replies and all(x.code == p.AccessAccept for x in replies)
    assert stack.erp.logins - before == 1


def test_slow_erp_does_not_block_other_logins(stack):
    import threading
    import time as t
    orig = stack.server.policy.erp.authenticate

    def slow(u, pw):
        if u == "olu@acme.test":
            t.sleep(2)
        return orig(u, pw)

    stack.server.policy.erp.authenticate = slow
    th = threading.Thread(target=stack.router.login, args=("olu@acme.test", "pw-olu"))
    th.start()
    t.sleep(0.2)
    start = t.monotonic()
    from fake_router import FakeRouter
    other = FakeRouter(stack.dictionary, stack.config.radius.auth_port,
                       stack.config.radius.acct_port, b"router-shared-secret")
    assert other.login("sam@acme.test", "pw-sam").code == packet.AccessAccept
    assert t.monotonic() - start < 1.5
    th.join()
    other.close()


def test_router_user_profile_and_address_list(stack):
    stack.config.radius.router_user_profile = "erpwifi"
    stack.config.profiles["guest"].address_list = "HS-GUEST"
    reply = stack.router.login("sam@acme.test", "pw-sam")
    assert attr(reply, "Mikrotik-Group") == "erpwifi"
    [code] = stack.db.create_vouchers(1, profile="guest", valid_minutes=60)
    reply = stack.router.login(code, code)
    assert attr(reply, "Mikrotik-Address-List") == "HS-GUEST"


def test_fail_closed_by_default_when_erpnext_down(stack):
    assert stack.router.login("sam@acme.test", "pw-sam").code == packet.AccessAccept
    stack.erp.down = True
    reply = stack.router.login("sam@acme.test", "pw-sam")
    assert reply.code == packet.AccessReject and "unavailable" in attr(reply, "Reply-Message")


def test_offline_grace_lets_recent_users_back_in(stack):
    stack.config.erpnext.offline_grace_hours = 12
    assert stack.router.login("sam@acme.test", "pw-sam").code == packet.AccessAccept
    stack.erp.down = True
    reply = stack.router.login("sam@acme.test", "pw-sam")
    assert reply.code == packet.AccessAccept
    assert attr(reply, "Mikrotik-Rate-Limit") == "10M/20M"  # cached staff profile
    assert stack.db.recent_auth()[0]["reason"].startswith("Welcome (offline")
    # wrong password, unknown user, and blocked user are still refused
    assert stack.router.login("sam@acme.test", "guess").code == packet.AccessReject
    assert stack.router.login("olu@acme.test", "pw-olu").code == packet.AccessReject
    stack.db.add_block("user", "sam@acme.test")
    assert stack.router.login("sam@acme.test", "pw-sam").code == packet.AccessReject


def test_offline_grace_expires_and_password_change_clears_cache(stack):
    stack.config.erpnext.offline_grace_hours = 1
    stack.router.login("sam@acme.test", "pw-sam")
    stack.db._conn.execute("UPDATE credential_cache SET verified_at = verified_at - 7200")
    stack.db._conn.commit()
    stack.erp.down = True
    assert stack.router.login("sam@acme.test", "pw-sam").code == packet.AccessReject

    stack.erp.down = False
    stack.router.login("sam@acme.test", "pw-sam")
    stack.erp.users["sam@acme.test"]["password"] = "new-pw"
    assert stack.router.login("sam@acme.test", "pw-sam").code == packet.AccessReject  # ERPNext says no
    stack.erp.down = True
    assert stack.router.login("sam@acme.test", "pw-sam").code == packet.AccessReject  # cache dropped


def test_reused_session_id_after_router_reboot(stack):
    """RouterOS restarts Acct-Session-Id numbering on reboot; a new user must not
    inherit the old row (that made Kick disconnect the wrong person)."""
    r = stack.router
    reply = r.login("sam@acme.test", "pw-sam")
    r.accounting("Start", "sam", "81000001", cls=reply["Class"][0], mac="AA:00:00:00:00:01")
    r.accounting("Interim-Update", "sam", "81000001", cls=reply["Class"][0],
                 mac="AA:00:00:00:00:01", download=10 * MB, seconds=300)
    # Router reboots without a Stop; after Accounting-On, ids start again.
    r.accounting("Accounting-On", "", "")
    reply = r.login("olu@acme.test", "pw-olu", mac="AA:00:00:00:00:02")
    r.accounting("Start", "olu", "81000001", cls=reply["Class"][0], mac="AA:00:00:00:00:02")
    [s] = stack.db.active_sessions()
    assert (s["username"], s["mac"], s["output_bytes"]) == ("olu@acme.test", "AA:00:00:00:00:02", 0)
    # Even without Accounting-On, a different user on the same id gets a new row
    reply = r.login("jane", "pw-jane", mac="AA:00:00:00:00:03")
    r.accounting("Start", "jane", "81000001", cls=reply["Class"][0], mac="AA:00:00:00:00:03")
    [s] = stack.db.active_sessions()
    assert s["username"] == "jane@acme.test"
    assert stack.db.usage_since("sam@acme.test", 0)[0] == 10 * MB


def test_retransmitted_start_and_stop_counted_once(stack):
    r = stack.router
    reply = r.login("sam@acme.test", "pw-sam")
    for _ in range(2):
        r.accounting("Start", "sam", "8100abcd", cls=reply["Class"][0])
    for _ in range(2):
        r.accounting("Stop", "sam", "8100abcd", cls=reply["Class"][0], download=5 * MB, seconds=60)
    assert stack.db.usage_since("sam@acme.test", 0) == (5 * MB, 60)
