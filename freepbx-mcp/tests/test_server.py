import json
import re
from pathlib import Path

import pytest

from freepbx_mcp.ami import AMIClient, AMIError, encode_action
from freepbx_mcp.config import (
    DEFAULT_DIAL_ALLOW,
    DEFAULT_DIAL_DENY,
    CallPolicy,
    CallPolicyError,
    Settings,
)
from freepbx_mcp.server import DEFAULT_EVENT_TYPES, create_server

from fake_ami import FakeAMI


def make_settings(port: int, tmp_path, **overrides) -> Settings:
    values = dict(
        ami_host="127.0.0.1",
        ami_port=port,
        ami_user="hermes",
        ami_secret="s3cret",
        dial_allow=re.compile(DEFAULT_DIAL_ALLOW),
        dial_deny=re.compile(DEFAULT_DIAL_DENY),
        extension_pattern=re.compile(r"^[0-9]{2,6}$"),
        caller_id="Hermes",
        dial_context="from-internal",
        max_calls_per_hour=2,
        read_only=False,
        asterisk_log=str(tmp_path / "full"),
        cdr_csv=str(tmp_path / "Master.csv"),
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
async def fake():
    ami = FakeAMI()
    port = await ami.start()
    ami.port = port
    yield ami
    await ami.stop()


@pytest.fixture
async def server(fake, tmp_path):
    settings = make_settings(fake.port, tmp_path)
    client = AMIClient("127.0.0.1", fake.port, "hermes", "s3cret",
                       keep_events=DEFAULT_EVENT_TYPES)
    srv = create_server(settings, client)
    srv.fake = fake
    srv.ami = client
    yield srv
    await client.close()


async def call(srv, name, **args) -> str:
    result = await srv.call_tool(name, args)
    return result.content[0].text


def test_encode_action_rejects_injection():
    with pytest.raises(ValueError):
        encode_action("Originate", {"Exten": "101\r\nAction: Command"})


async def test_bad_login(fake):
    client = AMIClient("127.0.0.1", fake.port, "hermes", "wrong")
    with pytest.raises(AMIError, match="login failed"):
        await client.connect()
    assert not client.connected


async def test_unreachable():
    client = AMIClient("127.0.0.1", 1, "hermes", "x", timeout=1)
    with pytest.raises(AMIError, match="cannot reach"):
        await client.connect()


async def test_command_joins_output_lines(server):
    out = json.loads(await call(server, "system_status"))
    assert out["uptime"] == "System uptime: 1 day\nLast reload: 2 hours"
    assert out["version"] == "ran core show version"


async def test_active_calls(server):
    out = json.loads(await call(server, "list_active_calls"))
    assert out["count"] == 1
    assert out["channels"][0]["ConnectedLineNum"] == "0712345678"


async def test_extensions_fall_back_to_chan_sip(server):
    out = json.loads(await call(server, "list_extensions"))
    assert out["driver"] == "sip"
    assert out["peers"][0]["Status"] == "OK (5 ms)"


async def test_cli_allowlist(server):
    assert (await call(server, "asterisk_cli", command="pjsip show endpoints")).startswith("ran")
    for bad in ("core restart now", "pjsip show auths", "manager show users",
                "database show", "core show help; core stop now"):
        assert (await call(server, "asterisk_cli", command=bad)).startswith("Error")


async def test_click_to_call(server):
    text = await call(server, "click_to_call", extension="101", number="102")
    assert "connected" in text
    sent = [a for a in server.fake.actions if a["Action"] == "Originate"][0]
    assert sent["Channel"] == "Local/101@from-internal"
    assert sent["Exten"] == "102"
    assert sent["Async"] == "true"


async def test_call_failure_reason(server):
    server.fake.originate_reason = "5"
    text = await call(server, "call_and_play", number="102", recording="custom/alert")
    assert "busy" in text


async def test_dial_policy(server):
    for number in ("+447700900123", "0044123456", "0712345678"):
        text = await call(server, "click_to_call", extension="101", number=number)
        assert text.startswith("Error"), number
    assert not [a for a in server.fake.actions if a.get("Action") == "Originate"]


async def test_bad_recording_name(server):
    text = await call(server, "call_and_play", number="102", recording="../../etc/passwd")
    assert text.startswith("Error")


async def test_rate_limit(server):
    await call(server, "click_to_call", extension="101", number="102")
    await call(server, "click_to_call", extension="101", number="103")
    text = await call(server, "click_to_call", extension="101", number="104")
    assert "limit" in text


async def test_read_only(fake, tmp_path):
    srv = create_server(make_settings(fake.port, tmp_path, read_only=True),
                        AMIClient("127.0.0.1", fake.port, "hermes", "s3cret"))
    assert "READ_ONLY" in await call(srv, "hangup_call", channel="PJSIP/101-1")


async def test_events_are_filtered(server):
    await server.ami.connect()
    server.fake.push_event(Event="VarSet", Variable="X")
    server.fake.push_event(Event="Hangup", Channel="PJSIP/101-1", Cause="16")
    await server.ami.command("core show version")  # round-trip so events land
    rows = json.loads(await call(server, "recent_events"))
    assert [r["Event"] for r in rows] == ["Hangup"]


async def test_recent_calls_from_cdr(server, tmp_path):
    (tmp_path / "Master.csv").write_text(
        '"","101","0712345678","from-internal","""Bob"" <101>","PJSIP/101-1","PJSIP/trunk-2",'
        '"Dial","PJSIP/0712345678@trunk","2026-09-24 10:00:00","2026-09-24 10:00:05",'
        '"2026-09-24 10:01:05","65","60","ANSWERED","DOCUMENTATION","1727.1",""\n'
    )
    rows = json.loads(await call(server, "recent_calls", number="0712345678"))
    assert rows[0]["disposition"] == "ANSWERED" and rows[0]["billsec"] == "60"


async def test_tools_are_annotated(server):
    tools = {t.name: t for t in await server.list_tools()}
    assert tools["list_active_calls"].annotations.read_only_hint is True
    for name in ("click_to_call", "call_and_play", "hangup_call"):
        assert not tools[name].annotations.read_only_hint


def test_policy_widening():
    settings = make_settings(0, Path("/tmp"), dial_allow=re.compile(r"^0[0-9]{9}$|^[0-9]{3}$"))
    policy = CallPolicy(settings)
    assert policy.check_number("071 234 5678") == "0712345678"
    with pytest.raises(CallPolicyError):
        policy.check_number("+254712345678")
