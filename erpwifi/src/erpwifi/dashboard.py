"""Admin dashboard: who is online, kick/block, vouchers, usage, sign-in log."""

from __future__ import annotations

import hmac
import ipaddress
import secrets
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import segno
from markupsafe import Markup

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .config import Config
from .db import Database, start_of_day
from .erpnext import ERPNextUnavailable
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


def _qr_svg(data: str) -> Markup:
    return Markup(segno.make(data, error="m").svg_inline(scale=5, border=2, dark="#000",
                                                         light="#fff"))


def _wifi_escape(value: str) -> str:
    return "".join("\\" + c if c in '\\;,:"' else c for c in value)


def create_app(config: Config, db: Database, disconnector=None, erp=None) -> Flask:
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
        pending = 0
        if session.get("role") and config.passes.requests_enabled:
            db.expire_requests(time.time() - config.passes.request_expire_minutes * 60)
            pending = db.count_requests("pending")
        return {"csrf": session["csrf"], "now": time.time(), "pending_requests": pending}

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

    def require(*roles):
        def decorator(view):
            @wraps(view)
            def wrapper(*args, **kwargs):
                role = session.get("role")
                if role is None:
                    return redirect(url_for("login", next=request.path))
                if role not in roles:
                    abort(403)
                return view(*args, **kwargs)
            return wrapper
        return decorator

    login_required = require("admin")
    pass_issuer = require("admin", "issuer")

    def check_login(username: str, password: str) -> tuple[str, str] | None:
        """(role, display name) for a local account or an ERP user with a dashboard role."""
        role = check_local_login(username, password)
        if role:
            return role, username
        dash = config.dashboard
        if erp is None or not (dash.erp_admin_roles or dash.erp_issuer_roles):
            return None
        try:
            user = erp.authenticate(username, password)
        except ERPNextUnavailable:
            flash("ERPNext is unreachable; use the local admin account", "error")
            return None
        if user is None or not user.enabled:
            return None
        if set(dash.erp_admin_roles) & set(user.roles):
            return "admin", user.user_id
        if set(dash.erp_issuer_roles) & set(user.roles):
            return "issuer", user.user_id
        return None

    def check_local_login(username: str, password: str) -> str | None:
        """Role of the matching local dashboard account, or None."""
        accounts = [("admin", config.dashboard.admin_username, config.dashboard.admin_password_hash)]
        accounts += [("issuer", i.username, i.password_hash) for i in config.dashboard.issuers]
        role = None
        for acct_role, acct_user, acct_hash in accounts:
            # check every account so timing doesn't reveal which usernames exist
            if (hmac.compare_digest(username, acct_user) and acct_hash
                    and check_password_hash(acct_hash, password)):
                role = acct_role
        return role

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # Captive-portal pages, so the router can download them with /tool fetch.
    @app.get("/hotspot/<name>")
    def hotspot_file(name):
        if name not in HOTSPOT_FILES:
            abort(404)
        page = (HOTSPOT_DIR / name).read_text()
        page = (page.replace("__PORTAL_URL__", config.dashboard.portal_url)
                    .replace("__ADMIN_URL__", config.dashboard.public_url))
        return page, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            found = check_login(username, request.form.get("password", ""))
            if found:
                role, display = found
                session.clear()
                session["role"] = role
                session["user"] = display
                home = url_for("online") if role == "admin" else url_for("passes")
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else home)
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
        return render_template("vouchers.html", vouchers=db.list_vouchers(kind="voucher"),
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

    @app.route("/passes", methods=["GET", "POST"])
    @pass_issuer
    def passes():
        cfg = config.passes
        if request.method == "POST":
            try:
                hours = int(request.form.get("hours", cfg.hours[0]))
                count = max(1, min(int(request.form.get("count", 1)), 20))
            except ValueError:
                abort(400)
            if hours not in cfg.hours:
                abort(400)
            codes = db.create_vouchers(
                count, profile=cfg.profile, valid_minutes=hours * 60,
                max_devices=cfg.max_devices, note=request.form.get("note", "")[:200],
                length=cfg.code_length, kind="pass", issued_by=session.get("user", ""))
            return redirect(url_for("show_passes", codes=",".join(codes)))
        recent = [v for v in db.list_vouchers(200, kind="pass")
                  if v.status(time.time()) in ("unused", "active")]
        return render_template("passes.html", cfg=cfg, recent=recent)

    @app.get("/passes/show")
    @pass_issuer
    def show_passes():
        cfg = config.passes
        codes = [c for c in request.args.get("codes", "").split(",") if c]
        found = [v for v in (db.get_voucher(c) for c in codes) if v and v.kind == "pass"]
        wifi_qr = None
        if cfg.wifi_ssid:
            security = "WPA" if cfg.wifi_password else "nopass"
            wifi_qr = _qr_svg(f"WIFI:T:{security};S:{_wifi_escape(cfg.wifi_ssid)};"
                              f"P:{_wifi_escape(cfg.wifi_password)};;")
        tickets = [{
            "pass": v,
            "qr": _qr_svg(cfg.login_url + "?" + urlencode({"username": v.code, "password": v.code})),
        } for v in found]
        return render_template("pass_show.html", cfg=cfg, tickets=tickets, wifi_qr=wifi_qr)

    @app.get("/requests")
    @pass_issuer
    def requests_page():
        return render_template(
            "requests.html", cfg=config.passes,
            pending=db.list_requests(("pending",)),
            decided=db.list_requests(("approved", "declined", "expired"), limit=30))

    @app.post("/requests/<int:pk>/approve")
    @pass_issuer
    def approve_request(pk):
        cfg = config.passes
        req = db.get_request(pk=pk)
        try:
            hours = int(request.form.get("hours", cfg.hours[0]))
        except ValueError:
            abort(400)
        if req is None or hours not in cfg.hours:
            abort(400)
        note = req["name"] + (f" ({req['organisation']})" if req["organisation"] else "")
        note += f", visiting {req['visiting']}" if req["visiting"] else ""
        [code] = db.create_vouchers(1, profile=cfg.profile, valid_minutes=hours * 60,
                                    max_devices=cfg.max_devices, note=note[:200],
                                    length=cfg.code_length, kind="pass",
                                    issued_by=session.get("user", ""))
        if not db.decide_request(pk, "approved", session.get("user", ""), pass_code=code):
            db.revoke_voucher(code)
            flash("Someone else already answered that request", "error")
            return redirect(url_for("requests_page"))
        flash(f"Approved {req['name']}: give them this code or let them scan the QR", "ok")
        return redirect(url_for("show_passes", codes=code))

    @app.post("/requests/<int:pk>/decline")
    @pass_issuer
    def decline_request(pk):
        if db.decide_request(pk, "declined", session.get("user", "")):
            flash("Request declined", "ok")
        return redirect(url_for("requests_page"))

    @app.post("/passes/<code>/revoke")
    @pass_issuer
    def revoke_pass(code):
        v = db.get_voucher(code)
        if v is None or v.kind != "pass":
            abort(404)
        db.revoke_voucher(v.code)
        for row in db.active_sessions(v.code):
            kick(row)
        flash(f"Revoked pass {v.code}", "ok")
        return redirect(url_for("passes"))

    @app.get("/log")
    @login_required
    def auth_log():
        return render_template("log.html", entries=db.recent_auth())

    return app
