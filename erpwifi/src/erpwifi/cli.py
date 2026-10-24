"""Command line entry point: `erpwifi run`, `erpwifi voucher`, `erpwifi check-erp`, ..."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
import threading
import time

from werkzeug.security import generate_password_hash

from .config import ConfigError, load_config
from .db import Database
from .erpnext import ERPNextClient, ERPNextUnavailable


def _load(args):
    try:
        return load_config(args.config)
    except (OSError, ConfigError) as exc:
        sys.exit(f"config error: {exc}")


def cmd_run(args):
    from waitress import serve

    from .dashboard import create_app
    from .policy import Policy
    from .radius import RadiusServer

    config = _load(args)
    if config.timezone:
        os.environ["TZ"] = config.timezone
        time.tzset()
    db = Database(config.database, stale_after=config.radius.interim_interval * 3 + 60)
    radius = RadiusServer(config, db, Policy(config, db, ERPNextClient(config.erpnext)))
    threading.Thread(target=radius.serve_forever, name="radius", daemon=True).start()
    if not config.dashboard.admin_password_hash:
        logging.warning("dashboard.admin_password_hash is empty: dashboard sign-in is disabled")
    app = create_app(config, db)
    logging.info("Dashboard on http://%s:%d", config.dashboard.listen, config.dashboard.port)
    serve(app, host=config.dashboard.listen, port=config.dashboard.port, threads=4)


def cmd_check_config(args):
    config = _load(args)
    print(f"OK: {len(config.radius.clients)} router(s), {len(config.profiles)} profile(s), "
          f"{len(config.rules)} rule(s)")


def cmd_check_erp(args):
    from .policy import Policy

    config = _load(args)
    password = getpass.getpass(f"ERPNext password for {args.username}: ")
    try:
        user = ERPNextClient(config.erpnext).authenticate(args.username, password)
    except ERPNextUnavailable as exc:
        sys.exit(f"ERPNext unavailable: {exc}")
    if user is None:
        sys.exit("ERPNext rejected the username or password")
    profile = Policy(config, None, None).profile_for(user)
    print(f"user:       {user.user_id} ({user.full_name})")
    print(f"enabled:    {user.enabled}")
    print(f"roles:      {', '.join(user.roles) or '(not looked up: no API token)'}")
    print(f"department: {user.department or '—'}")
    print(f"profile:    {profile.name} (rate {profile.rate_limit or 'unlimited'})")


def cmd_voucher(args):
    config = _load(args)
    profile = args.profile or config.vouchers.default_profile
    if profile not in config.profiles:
        sys.exit(f"unknown profile '{profile}'")
    codes = Database(config.database).create_vouchers(
        args.count, profile=profile, valid_minutes=args.minutes or config.vouchers.default_minutes,
        max_devices=args.devices, data_mb=args.data_mb, note=args.note,
        length=config.vouchers.code_length)
    print("\n".join(codes))


def cmd_hash_password(args):
    password = getpass.getpass("New dashboard password: ")
    if password != getpass.getpass("Repeat: "):
        sys.exit("passwords differ")
    print(generate_password_hash(password))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="erpwifi")
    parser.add_argument("-c", "--config", default=os.environ.get("ERPWIFI_CONFIG", "config.toml"))
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the RADIUS server and dashboard").set_defaults(func=cmd_run)
    sub.add_parser("check-config", help="validate the config file").set_defaults(func=cmd_check_config)
    p = sub.add_parser("check-erp", help="test an ERPNext sign-in and show the profile it gets")
    p.add_argument("username")
    p.set_defaults(func=cmd_check_erp)
    p = sub.add_parser("voucher", help="create guest vouchers")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--profile")
    p.add_argument("--minutes", type=int)
    p.add_argument("--devices", type=int, default=1)
    p.add_argument("--data-mb", type=int, default=0)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_voucher)
    sub.add_parser("hash-password", help="hash a dashboard password").set_defaults(func=cmd_hash_password)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
