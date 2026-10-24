import socket
import threading

import pytest

from erpwifi.config import parse_config
from erpwifi.db import Database
from erpwifi.erpnext import ERPNextClient
from erpwifi.policy import Policy
from erpwifi.radius import RadiusServer, load_dictionary

from fake_erpnext import API_KEY, API_SECRET, FakeERPNext
from fake_router import FakeRouter

SECRET = "router-shared-secret"


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def erp():
    fake = FakeERPNext()
    fake.add_user("jane@acme.test", "pw-jane", username="jane", full_name="Jane Doe",
                  roles=["Employee", "System Manager"], department="IT - ACME")
    fake.add_user("sam@acme.test", "pw-sam", full_name="Sam Sales",
                  roles=["Employee"], department="Sales - ACME")
    fake.add_user("olu@acme.test", "pw-olu", roles=["Employee"], department="Operations - ACME")
    fake.add_user("cust@acme.test", "pw-cust", roles=["Customer"])
    fake.add_user("gone@acme.test", "pw-gone", roles=["Employee"], enabled=False)
    fake.add_user("left@acme.test", "pw-left", roles=["Employee"], department="IT - ACME",
                  employee_status="Left")
    yield fake
    fake.close()


def make_config(erp_url, auth_port, acct_port, coa_port, db_path):
    return parse_config({
        "radius": {"listen": "127.0.0.1", "auth_port": auth_port, "acct_port": acct_port,
                   "interim_interval": 60,
                   "clients": [{"address": "127.0.0.1", "secret": SECRET, "name": "0. Firewall",
                                "coa_port": coa_port}]},
        "erpnext": {"url": erp_url, "api_key": API_KEY, "api_secret": API_SECRET,
                    "timeout": 3, "require_roles": ["Employee"]},
        "profiles": {
            "default": {"rate_limit": "2M/5M", "session_timeout": 28800, "daily_data_mb": 1024,
                        "max_devices": 2},
            "staff": {"rate_limit": "10M/20M", "max_devices": 3},
            "admin": {},
            "guest": {"rate_limit": "1M/2M", "session_timeout": 3600},
        },
        "rules": [{"role": "System Manager", "profile": "admin"},
                  {"department": "Sales", "profile": "staff"}],
        "policy": {"default_profile": "default"},
        "vouchers": {"default_profile": "guest", "default_minutes": 120},
        "dashboard": {"secret_key": "test"},
        "database": {"path": db_path},
    })


@pytest.fixture
def stack(erp, tmp_path):
    auth_port, acct_port = free_udp_port(), free_udp_port()
    dictionary = load_dictionary()
    router = FakeRouter(dictionary, auth_port, acct_port, SECRET.encode())
    config = make_config(erp.url, auth_port, acct_port, router.coa_port,
                         str(tmp_path / "wifi.db"))
    db = Database(config.database, stale_after=240)
    server = RadiusServer(config, db, Policy(config, db, ERPNextClient(config.erpnext)),
                          dictionary=dictionary)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    class Stack:
        pass

    s = Stack()
    s.config, s.db, s.router, s.erp, s.server, s.dictionary = config, db, router, erp, server, dictionary
    yield s
    server.shutdown()
    thread.join(2)
    server.close()
    router.close()
