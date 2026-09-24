# freepbx-mcp

An MCP server that connects [Hermes Agent](https://github.com/NousResearch/hermes-agent)
to FreePBX, so Hermes can monitor the phone system and place calls.

It talks to Asterisk over the Asterisk Manager Interface (AMI). Hermes starts
it as an MCP server and gets the tools below as `mcp_freepbx_<tool>`.

```
Hermes Agent ──stdio (or ssh)──▶ freepbx-mcp ──AMI :5038──▶ Asterisk (FreePBX)
```

## Tools

| Tool | What it does | Needs approval with `trust: untrusted` |
|---|---|---|
| `system_status` | Asterisk version, uptime, active call count | no |
| `list_active_calls` | Every live channel: who is talking to whom, and for how long | no |
| `list_extensions` | PJSIP endpoints with device state (chan_sip fallback) | no |
| `trunk_status` | Trunk registrations and contact reachability | no |
| `queue_status` | Queue callers waiting, hold times, available agents | no |
| `recent_events` | Recent hangups, registration changes, failed SIP logins | no |
| `recent_calls` | Call history from the CDR CSV | no |
| `asterisk_log` | Tail and filter `/var/log/asterisk/full` | no |
| `asterisk_cli` | Read-only CLI (`core show …`, `pjsip show …`, and so on) | no |
| `host_health` | Load, memory and disk of the PBX machine | no |
| `click_to_call` | Ring an extension, then connect it to a number | **yes** |
| `call_and_play` | Call a number and play a recording, for alerts and reminders | **yes** |
| `hangup_call` | Hang up a channel | **yes** |

## Safety

- **Dial policy.** By default only internal extensions (2 to 6 digits) can be
  called. International and premium prefixes (`+`, `00`, `011`, `900`) are always
  refused. Widen `FREEPBX_DIAL_ALLOW` on purpose when you want Hermes to call
  outside numbers.
- **Rate limit.** At most `FREEPBX_MAX_CALLS_PER_HOUR` calls (20 by default).
- **Read-only mode.** Set `FREEPBX_READ_ONLY=1` to allow monitoring only.
- **The CLI tool is read-only.** It accepts `show`/`list` commands only and
  refuses anything that prints credentials.
- **Minimal AMI user.** It is limited to localhost and has no `system` or
  `config` rights.
- **Approval before calls.** The monitoring tools are marked read-only. With
  `trust: untrusted`, Hermes asks you before every call or hangup.

## Install on the FreePBX server

This needs Python 3.10 or newer. FreePBX 17 on Debian 12 ships 3.11.

```bash
git clone https://github.com/97newest/Newton.git
cd Newton
sudo bash freepbx-mcp/deploy/install.sh
```

The script does four things:

1. Installs the server into `/opt/freepbx-mcp/venv`.
2. Adds an AMI user `[hermes]` with a random secret to
   `/etc/asterisk/manager_custom.conf`, then reloads the manager.
3. Writes `/etc/freepbx-mcp.env` (mode 0640, group `asterisk`).
4. Connects to AMI and prints the Asterisk version as a check.

Then add the user that runs Hermes to the `asterisk` group, so it can read
the env file and the logs:

```bash
sudo usermod -aG asterisk <hermes-user>
```

## Connect Hermes

Add this to `~/.hermes/config.yaml` and restart Hermes:

```yaml
mcp_servers:
  freepbx:
    command: "/opt/freepbx-mcp/venv/bin/freepbx-mcp"
    timeout: 90
    trust: untrusted
```

If Hermes runs on a different machine, launch the server over SSH instead.
That way no port is opened and the AMI secret stays on the PBX. See
[`deploy/hermes-config.example.yaml`](deploy/hermes-config.example.yaml).

Check that the tools loaded by asking Hermes: *"What's the status of the phone
system?"*

## Things to ask Hermes

- "Are all my trunks registered?"
- "Who is on a call right now?"
- "Show me failed SIP login attempts from the last hour."
- "Ring extension 101 and connect it to 102."
- "Call 101 and play custom/server-alert."

  Record the message first in FreePBX under **Admin → System Recordings**,
  then refer to it as `custom/<name>`.

For ongoing monitoring, use Hermes' scheduled tasks. For example:
*"Every 15 minutes, check trunk_status and recent_events. If a trunk is not
registered, or there are more than 10 failed logins, message me on Telegram
and call extension 101 with custom/pbx-alert."*

## Configuration

Settings are read from environment variables. Anything not already set is
filled from `/etc/freepbx-mcp.env`, or from the file named in
`FREEPBX_MCP_ENV_FILE`. See
[`deploy/freepbx-mcp.env.example`](deploy/freepbx-mcp.env.example) for every
option.

## Development

```bash
cd freepbx-mcp
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

The tests run against a fake AMI server in `tests/fake_ami.py`, so they don't
need Asterisk.
