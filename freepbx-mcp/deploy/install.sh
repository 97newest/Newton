#!/usr/bin/env bash
# Install the FreePBX MCP server on the FreePBX machine. Run as root:
#   sudo bash freepbx-mcp/deploy/install.sh
# Safe to re-run: it keeps an existing AMI user and env file.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/freepbx-mcp
ENV_FILE=/etc/freepbx-mcp.env
MANAGER_CUSTOM=/etc/asterisk/manager_custom.conf
AMI_USER=hermes

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
command -v asterisk >/dev/null || { echo "asterisk not found - run this on the FreePBX server"; exit 1; }

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "Python 3.10+ is required (found $(python3 --version 2>&1))."
  echo "FreePBX 17 on Debian 12 ships 3.11; on older systems install a newer python3 first."
  exit 1
fi
python3 -m venv --help >/dev/null 2>&1 || { echo "install python3-venv first: apt install python3-venv"; exit 1; }

echo "==> Installing into $PREFIX"
mkdir -p "$PREFIX"
[ -x "$PREFIX/venv/bin/python" ] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet "$SRC_DIR"

if grep -q "^\[$AMI_USER\]" "$MANAGER_CUSTOM" 2>/dev/null; then
  echo "==> AMI user [$AMI_USER] already exists in $MANAGER_CUSTOM, keeping it"
  SECRET=""
else
  echo "==> Adding AMI user [$AMI_USER] to $MANAGER_CUSTOM"
  SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
  sed "s/CHANGE_ME_TO_A_LONG_RANDOM_SECRET/$SECRET/" \
    "$SRC_DIR/deploy/manager_custom.conf.example" >> "$MANAGER_CUSTOM"
  chown asterisk:asterisk "$MANAGER_CUSTOM" 2>/dev/null || true
  asterisk -rx "manager reload" >/dev/null
fi

if [ -f "$ENV_FILE" ]; then
  echo "==> Keeping existing $ENV_FILE"
  if [ -n "$SECRET" ]; then
    echo "    NOTE: a new AMI secret was generated; set FREEPBX_AMI_SECRET=$SECRET in $ENV_FILE"
  fi
else
  if [ -z "$SECRET" ]; then
    echo "==> Writing $ENV_FILE - fill in FREEPBX_AMI_SECRET from $MANAGER_CUSTOM"
    cp "$SRC_DIR/deploy/freepbx-mcp.env.example" "$ENV_FILE"
  else
    echo "==> Writing $ENV_FILE"
    sed "s/^FREEPBX_AMI_SECRET=.*/FREEPBX_AMI_SECRET=$SECRET/" \
      "$SRC_DIR/deploy/freepbx-mcp.env.example" > "$ENV_FILE"
  fi
  chown root:asterisk "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
fi

echo "==> Checking the AMI connection"
"$PREFIX/venv/bin/python" - <<'EOF'
import asyncio
from freepbx_mcp.ami import AMIClient
from freepbx_mcp.config import Settings

async def main():
    s = Settings.from_env()
    ami = AMIClient(s.ami_host, s.ami_port, s.ami_user, s.ami_secret)
    await ami.connect()
    print("   ", (await ami.command("core show version")).splitlines()[0])
    print("   ", len(await ami.list_action("CoreShowChannels")), "active channels")
    await ami.close()

asyncio.run(main())
EOF

cat <<EOF

Done. Add this to ~/.hermes/config.yaml on the machine running Hermes:

mcp_servers:
  freepbx:
    command: "$PREFIX/venv/bin/freepbx-mcp"
    timeout: 90
    trust: untrusted

(If Hermes runs on another machine, see deploy/hermes-config.example.yaml.)
The user that runs Hermes must be able to read $ENV_FILE: add it to the
asterisk group (usermod -aG asterisk <user>) so it can also read the logs.
EOF
