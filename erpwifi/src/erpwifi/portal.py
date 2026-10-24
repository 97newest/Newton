"""Visitor-facing pages: ask for temporary access and wait for approval.

Served on its own port, which the router lets hotspot users reach before they
sign in (walled garden). It never shows a pass code: whoever approves the
request hands the code or QR code over in person.
"""

from __future__ import annotations

import hmac
import secrets
import time

from flask import Flask, abort, redirect, render_template, request, session, url_for

from .config import Config
from .db import Database

# Requests one device may send per window.
MAX_PER_IP = 3
IP_WINDOW = 600


def create_portal_app(config: Config, db: Database) -> Flask:
    app = Flask(__name__)
    app.secret_key = (config.dashboard.secret_key or secrets.token_hex(32)) + ":portal"
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_NAME="erpwifi_portal")
    cfg = config.passes
    sign_in_url = cfg.login_url

    def expire():
        db.expire_requests(time.time() - cfg.request_expire_minutes * 60)

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return {"csrf": session["csrf"], "sign_in_url": sign_in_url}

    @app.before_request
    def gate():
        if not cfg.requests_enabled and request.endpoint != "healthz":
            abort(404)
        if request.method == "POST" and not hmac.compare_digest(
                request.form.get("csrf", ""), session.get("csrf", "")):
            abort(400, "Form expired, reload the page")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/")
    def index():
        return redirect(url_for("request_form", **request.args))

    @app.route("/request", methods=["GET", "POST"])
    def request_form():
        error = ""
        form = request.form if request.method == "POST" else {}
        if request.method == "POST":
            expire()
            ip = request.remote_addr or ""
            name = form.get("name", "").strip()[:100]
            if not name or not form.get("visiting", "").strip():
                error = "Please enter your name and who you are visiting."
            elif db.count_requests("pending", ip=ip, since=time.time() - IP_WINDOW) >= MAX_PER_IP:
                error = "This device already has requests waiting. Please ask at reception."
            elif db.count_requests("pending") >= cfg.max_pending_requests:
                error = "Too many requests are waiting right now. Please ask at reception."
            else:
                token = db.create_request(
                    name=name,
                    organisation=form.get("organisation", "").strip()[:100],
                    visiting=form.get("visiting", "").strip()[:100],
                    reason=form.get("reason", "").strip()[:200],
                    phone=form.get("phone", "").strip()[:30],
                    ip=ip, mac=form.get("mac", "")[:17])
                return redirect(url_for("request_status", token=token))
        return render_template("portal_request.html", error=error, form=form,
                               mac=request.values.get("mac", "")[:17])

    @app.get("/request/<token>")
    def request_status(token):
        expire()
        req = db.get_request(token=token)
        if req is None:
            abort(404)
        return render_template("portal_status.html", req=req, cfg=cfg)

    return app
