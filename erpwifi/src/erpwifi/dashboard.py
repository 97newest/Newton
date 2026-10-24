"""Admin dashboard: who is online, kick/block, vouchers, usage, sign-in log."""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import time
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template, request, send_from_directory,
                   session, url_for)
from werkzeug.security import check_password_hash

from .config import Config
from .db import Database, start_of_day
from .radius import disconnect, load_dictionary

HOTSPOT_DIR = Path(__file__).parent / "hotspot"
HOTSPOT_FILES = {p.name for p in HOTSPOT_DIR.glob("*.html")}


def _fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_duration(seconds) -> str:
    seconds = int(seconds or 0)
    h, rem = divmod(seconds, 3600)
    return f"{h}h {rem // 60:02d}m" if h else f"{rem // 60}m {rem % 60:02d}s"


def _fmt_time(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"


def create_app(config: Config, db: Database, disconnector=None) -> Flask:
    app = Flask(__name__)
    app.secret_key = config.dashboard.secret_key or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    app.jinja_env.filters.update(bytes=_fmt_bytes, duration=_fmt_duration, time=_fmt_time)
    dictionary = load_dictionary()

    def kick(row) -> bool:
        client = config.client_for(row["nas_ip"])
        if client is None:
            return False
        send = disconnector or (lambda **kw: disconnect(client, dictionary, **kw))
        return send(username=row["username"], session_id=row["acct_session_id"], ip=row["ip"])

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return {"csrf": session["csrf"], "now": time.time()}

    allowed = [ipaddress.ip_network(n, strict=False) for n in config.dashboard.allowed_networks]

    @app.before_request
    def check_source():
        if not allowed or request.endpoint in ("healthz", "hotspot_file"):
            return
        try:
            addr = ipaddress.ip_address(request.remote_addr or "")
        except ValueError:
            abort(403)
        if not any(addr in net for net in allowed):
            abort(403)

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            token = request.form.get("csrf", "")
            if not hmac.compare_digest(token, session.get("csrf", "")):
                abort(400, "Invalid form token, reload the page")

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("admin"):
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapper

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # Captive-portal pages, so the router can download them with /tool fetch.
    @app.get("/hotspot/<name>")
    def hotspot_file(name):
        if name not in HOTSPOT_FILES:
            abort(404)
        return send_from_directory(HOTSPOT_DIR, name, mimetype="text/html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user_ok = hmac.compare_digest(request.form.get("username", ""),
                                          config.dashboard.admin_username)
            pw_hash = config.dashboard.admin_password_hash
            pw_ok = bool(pw_hash) and check_password_hash(pw_hash, request.form.get("password", ""))
            if user_ok and pw_ok:
                session.clear()
                session["admin"] = True
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//")
                                else url_for("online"))
            time.sleep(1)
            flash("Wrong username or password", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def online():
        return render_template("online.html", sessions=db.active_sessions())

    @app.post("/sessions/<int:pk>/kick")
    @login_required
    def kick_session(pk):
        row = db.get_session(pk)
        if row is None:
            abort(404)
        if kick(row):
            flash(f"Disconnected {row['username']}", "ok")
        else:
            flash(f"Router did not confirm disconnecting {row['username']}", "error")
        return redirect(url_for("online"))

    @app.post("/blocks")
    @login_required
    def add_block():
        kind = request.form.get("kind")
        value = request.form.get("value", "").strip()
        if kind not in ("user", "mac") or not value:
            abort(400)
        db.add_block(kind, value, request.form.get("reason", ""))
        kicked = 0
        for row in db.active_sessions():
            match = (row["username"].lower() == value.lower() if kind == "user"
                     else row["mac"] == value.upper().replace("-", ":"))
            if match and kick(row):
                kicked += 1
        flash(f"Blocked {kind} {value}" + (f", disconnected {kicked} session(s)" if kicked else ""),
              "ok")
        return redirect(request.form.get("back") or url_for("users"))

    @app.post("/blocks/delete")
    @login_required
    def remove_block():
        db.remove_block(request.form.get("kind", ""), request.form.get("value", ""))
        flash("Unblocked", "ok")
        return redirect(url_for("users"))

    @app.get("/users")
    @login_required
    def users():
        return render_template("users.html", usage=db.usage_report(start_of_day(time.time())),
                               blocks=db.list_blocks())

    @app.route("/vouchers", methods=["GET", "POST"])
    @login_required
    def vouchers():
        if request.method == "POST":
            try:
                count = max(1, min(int(request.form.get("count", 1)), 500))
                minutes = max(1, int(request.form.get("minutes") or config.vouchers.default_minutes))
                devices = max(1, int(request.form.get("devices", 1)))
                data_mb = max(0, int(request.form.get("data_mb") or 0))
            except ValueError:
                abort(400)
            profile = request.form.get("profile", config.vouchers.default_profile)
            if profile not in config.profiles:
                abort(400)
            codes = db.create_vouchers(count, profile=profile, valid_minutes=minutes,
                                       max_devices=devices, data_mb=data_mb,
                                       note=request.form.get("note", "")[:200],
                                       length=config.vouchers.code_length)
            flash(f"Created {len(codes)} voucher(s)", "ok")
            return redirect(url_for("print_vouchers", codes=",".join(codes)))
        return render_template("vouchers.html", vouchers=db.list_vouchers(),
                               profiles=sorted(config.profiles), defaults=config.vouchers)

    @app.get("/vouchers/print")
    @login_required
    def print_vouchers():
        codes = [c for c in request.args.get("codes", "").split(",") if c]
        found = [v for v in (db.get_voucher(c) for c in codes) if v]
        return render_template("print.html", vouchers=found)

    @app.post("/vouchers/<code>/revoke")
    @login_required
    def revoke_voucher(code):
        db.revoke_voucher(code)
        for row in db.active_sessions(code):
            kick(row)
        flash(f"Revoked {code}", "ok")
        return redirect(url_for("vouchers"))

    @app.get("/log")
    @login_required
    def auth_log():
        return render_template("log.html", entries=db.recent_auth())

    return app
