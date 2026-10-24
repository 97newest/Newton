"""SQLite storage for sessions, vouchers, blocks and the sign-in log."""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nas_ip TEXT NOT NULL,
    acct_session_id TEXT NOT NULL,
    username TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT '',
    profile TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    started_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    stopped_at REAL,
    input_bytes INTEGER NOT NULL DEFAULT 0,
    output_bytes INTEGER NOT NULL DEFAULT 0,
    session_time INTEGER NOT NULL DEFAULT 0,
    terminate_cause TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_nas ON sessions (nas_ip, acct_session_id);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (username, started_at);
CREATE TABLE IF NOT EXISTS vouchers (
    code TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    valid_minutes INTEGER NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 1,
    data_mb INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    first_used_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0,
    -- 'voucher' (clock starts at first use) or 'pass' (fixed expiry)
    kind TEXT NOT NULL DEFAULT 'voucher',
    expires_fixed REAL,
    issued_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS blocks (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    organisation TEXT NOT NULL DEFAULT '',
    visiting TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    decided_at REAL,
    decided_by TEXT NOT NULL DEFAULT '',
    pass_code TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS credential_cache (
    login TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    verified_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    username TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    nas_ip TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    profile TEXT NOT NULL DEFAULT ''
);
"""

# Letters and digits that can't be confused with each other when printed.
VOUCHER_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


@dataclass
class Voucher:
    code: str
    profile: str
    valid_minutes: int
    max_devices: int
    data_mb: int
    note: str
    created_at: float
    first_used_at: float | None
    revoked: bool
    kind: str = "voucher"
    expires_fixed: float | None = None
    issued_by: str = ""

    @property
    def expires_at(self) -> float | None:
        if self.expires_fixed is not None:
            return self.expires_fixed
        if self.first_used_at is None:
            return None
        return self.first_used_at + self.valid_minutes * 60

    def status(self, now: float) -> str:
        if self.revoked:
            return "revoked"
        if self.expires_at is not None and now >= self.expires_at:
            return "expired"
        return "unused" if self.first_used_at is None else "active"


def normalize_mac(mac: str) -> str:
    return mac.strip().upper().replace("-", ":")


def start_of_day(now: float) -> float:
    t = time.localtime(now)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))


class Database:
    def __init__(self, path: str, stale_after: int = 960):
        self.path = path
        # A session without an accounting update for this long is treated as
        # gone (the router rebooted or lost its stop packet).
        self.stale_after = stale_after
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    @contextmanager
    def _tx(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    # -- sessions -------------------------------------------------------

    # Routers restart their Acct-Session-Id counter on reboot, so the same id can
    # name a new session. A row belongs to an accounting packet only if the user
    # and device agree, and, once the row is stopped, the start time too (a
    # retransmitted Stop). A reboot's Accounting-On closes the router's rows.
    SAME_SESSION_SLACK = 600

    def _find_session(self, c, nas_ip, session_id, username, mac, started_at, open_only=False):
        rows = c.execute(
            "SELECT id, username, mac, started_at, stopped_at FROM sessions "
            "WHERE nas_ip = ? AND acct_session_id = ? ORDER BY id DESC",
            (nas_ip, session_id),
        ).fetchall()
        for row in rows:
            if row["username"] != username or row["mac"] != normalize_mac(mac):
                continue
            if row["stopped_at"] is None:
                return row["id"]
            if not open_only and abs(row["started_at"] - started_at) <= self.SAME_SESSION_SLACK:
                return row["id"]
        return None

    def _insert_session(self, c, nas_ip, session_id, username, kind, profile, mac, ip,
                        started_at, now):
        # Any other open row with this id is a session the router forgot.
        c.execute(
            "UPDATE sessions SET stopped_at = ?, terminate_cause = 'replaced' "
            "WHERE nas_ip = ? AND acct_session_id = ? AND stopped_at IS NULL",
            (now, nas_ip, session_id),
        )
        return c.execute(
            """INSERT INTO sessions (nas_ip, acct_session_id, username, kind, profile,
                                     mac, ip, started_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (nas_ip, session_id, username, kind, profile, normalize_mac(mac), ip, started_at, now),
        ).lastrowid

    def acct_start(self, *, nas_ip, session_id, username, kind, profile, mac, ip, now=None):
        now = now or time.time()
        with self._tx() as c:
            pk = self._find_session(c, nas_ip, session_id, username, mac, now, open_only=True)
            if pk is not None:  # retransmitted Start
                c.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (now, pk))
                return
            self._insert_session(c, nas_ip, session_id, username, kind, profile, mac, ip, now, now)

    def acct_update(self, *, nas_ip, session_id, username, input_bytes, output_bytes,
                    session_time, mac="", ip="", kind="", profile="", stop=False, cause="", now=None):
        now = now or time.time()
        started_at = now - session_time
        with self._tx() as c:
            pk = self._find_session(c, nas_ip, session_id, username, mac, started_at)
            if pk is None:
                # Interim or stop for a session whose start we missed.
                pk = self._insert_session(c, nas_ip, session_id, username, kind, profile, mac,
                                          ip, started_at, now)
            c.execute(
                """UPDATE sessions SET input_bytes = ?, output_bytes = ?, session_time = ?,
                          updated_at = ?, stopped_at = ?, terminate_cause = ?,
                          ip = CASE WHEN ? != '' THEN ? ELSE ip END
                   WHERE id = ?""",
                (input_bytes, output_bytes, session_time, now, now if stop else None, cause,
                 ip, ip, pk),
            )

    def close_nas_sessions(self, nas_ip: str, cause: str, now=None):
        now = now or time.time()
        with self._tx() as c:
            c.execute(
                "UPDATE sessions SET stopped_at = ?, terminate_cause = ? "
                "WHERE nas_ip = ? AND stopped_at IS NULL",
                (now, cause, nas_ip),
            )

    def active_sessions(self, username: str | None = None, now=None) -> list[sqlite3.Row]:
        now = now or time.time()
        sql = "SELECT * FROM sessions WHERE stopped_at IS NULL AND updated_at >= ?"
        args: list = [now - self.stale_after]
        if username is not None:
            sql += " AND username = ?"
            args.append(username)
        with self._lock:
            return self._conn.execute(sql + " ORDER BY started_at DESC", args).fetchall()

    def get_session(self, session_pk: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute("SELECT * FROM sessions WHERE id = ?", (session_pk,)).fetchone()

    def usage_since(self, username: str, since: float) -> tuple[int, int]:
        """Bytes and seconds used by the user in sessions started since `since`."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(input_bytes + output_bytes), 0), COALESCE(SUM(session_time), 0) "
                "FROM sessions WHERE username = ? AND started_at >= ?",
                (username, since),
            ).fetchone()
        return int(row[0]), int(row[1])

    def usage_report(self, since: float) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                """SELECT username, kind, MAX(profile) AS profile, COUNT(*) AS sessions,
                          SUM(input_bytes) AS upload, SUM(output_bytes) AS download,
                          SUM(session_time) AS seconds, MAX(updated_at) AS last_seen
                   FROM sessions WHERE started_at >= ?
                   GROUP BY username, kind ORDER BY download + upload DESC""",
                (since,),
            ).fetchall()

    # -- vouchers -------------------------------------------------------

    def create_vouchers(self, count: int, *, profile: str, valid_minutes: int, max_devices: int = 1,
                        data_mb: int = 0, note: str = "", length: int = 8, kind: str = "voucher",
                        issued_by: str = "") -> list[str]:
        """Create codes. A 'pass' expires valid_minutes after issue, used or not;
        a 'voucher' runs for valid_minutes from its first use."""
        codes = []
        now = time.time()
        expires_fixed = now + valid_minutes * 60 if kind == "pass" else None
        with self._tx() as c:
            while len(codes) < count:
                code = "".join(secrets.choice(VOUCHER_ALPHABET) for _ in range(length))
                try:
                    c.execute(
                        """INSERT INTO vouchers (code, profile, valid_minutes, max_devices,
                                                 data_mb, note, created_at, kind, expires_fixed,
                                                 issued_by)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (code, profile, valid_minutes, max_devices, data_mb, note, now, kind,
                         expires_fixed, issued_by),
                    )
                except sqlite3.IntegrityError:
                    continue
                codes.append(code)
        return codes

    def get_voucher(self, code: str) -> Voucher | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vouchers WHERE code = ?", (code.strip().upper(),)
            ).fetchone()
        if row is None:
            return None
        return Voucher(**{**dict(row), "revoked": bool(row["revoked"])})

    def list_vouchers(self, limit: int = 500, kind: str | None = None) -> list[Voucher]:
        sql, args = "SELECT * FROM vouchers", []
        if kind is not None:
            sql += " WHERE kind = ?"
            args.append(kind)
        with self._lock:
            rows = self._conn.execute(
                sql + " ORDER BY created_at DESC LIMIT ?", (*args, limit)
            ).fetchall()
        return [Voucher(**{**dict(r), "revoked": bool(r["revoked"])}) for r in rows]

    def mark_voucher_used(self, code: str, now=None):
        with self._tx() as c:
            c.execute(
                "UPDATE vouchers SET first_used_at = ? WHERE code = ? AND first_used_at IS NULL",
                (now or time.time(), code),
            )

    def revoke_voucher(self, code: str):
        with self._tx() as c:
            c.execute("UPDATE vouchers SET revoked = 1 WHERE code = ?", (code,))

    # -- blocks ---------------------------------------------------------

    def add_block(self, kind: str, value: str, reason: str = ""):
        value = normalize_mac(value) if kind == "mac" else value.strip().lower()
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO blocks (kind, value, reason, created_at) VALUES (?, ?, ?, ?)",
                (kind, value, reason, time.time()),
            )

    def remove_block(self, kind: str, value: str):
        with self._tx() as c:
            c.execute("DELETE FROM blocks WHERE kind = ? AND value = ?", (kind, value))

    def is_blocked(self, username: str, mac: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT kind FROM blocks WHERE (kind = 'user' AND value = ?) OR (kind = 'mac' AND value = ?)",
                (username.strip().lower(), normalize_mac(mac)),
            ).fetchone()
        return row["kind"] if row else None

    def list_blocks(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM blocks ORDER BY created_at DESC").fetchall()

    # -- visitor access requests ---------------------------------------

    def expire_requests(self, older_than: float):
        with self._tx() as c:
            c.execute("UPDATE access_requests SET status = 'expired' "
                      "WHERE status = 'pending' AND created_at < ?", (older_than,))

    def create_request(self, *, name, organisation="", visiting="", reason="", phone="",
                       ip="", mac="") -> str:
        token = secrets.token_urlsafe(16)
        with self._tx() as c:
            c.execute(
                """INSERT INTO access_requests (token, name, organisation, visiting, reason,
                                                phone, ip, mac, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (token, name, organisation, visiting, reason, phone, ip,
                 normalize_mac(mac), time.time()),
            )
        return token

    def count_requests(self, status: str = "pending", ip: str | None = None,
                       since: float = 0) -> int:
        sql = "SELECT COUNT(*) FROM access_requests WHERE status = ? AND created_at >= ?"
        args: list = [status, since]
        if ip is not None:
            sql += " AND ip = ?"
            args.append(ip)
        with self._lock:
            return self._conn.execute(sql, args).fetchone()[0]

    def get_request(self, *, token: str | None = None, pk: int | None = None):
        col, val = ("token", token) if token is not None else ("id", pk)
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM access_requests WHERE {col} = ?", (val,)).fetchone()

    def list_requests(self, statuses: tuple[str, ...], limit: int = 100) -> list[sqlite3.Row]:
        marks = ",".join("?" * len(statuses))
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM access_requests WHERE status IN ({marks}) "
                "ORDER BY created_at DESC LIMIT ?", (*statuses, limit)).fetchall()

    def decide_request(self, pk: int, status: str, by: str, pass_code: str = "") -> bool:
        """Approve or decline a pending request; False if it was no longer pending."""
        with self._tx() as c:
            cur = c.execute(
                "UPDATE access_requests SET status = ?, decided_at = ?, decided_by = ?, "
                "pass_code = ? WHERE id = ? AND status = 'pending'",
                (status, time.time(), by, pass_code, pk))
            return cur.rowcount == 1

    # -- offline sign-in cache -----------------------------------------

    def remember_credential(self, login: str, user_id: str, profile: str, password_hash: str):
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO credential_cache (login, user_id, profile, password_hash, "
                "verified_at) VALUES (?, ?, ?, ?, ?)",
                (login.strip().lower(), user_id, profile, password_hash, time.time()),
            )

    def cached_credential(self, login: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM credential_cache WHERE login = ?", (login.strip().lower(),)
            ).fetchone()

    def forget_credential(self, login: str):
        with self._tx() as c:
            c.execute("DELETE FROM credential_cache WHERE login = ?", (login.strip().lower(),))

    # -- sign-in log ----------------------------------------------------

    def log_auth(self, username, mac, nas_ip, result, reason="", profile=""):
        with self._tx() as c:
            c.execute(
                "INSERT INTO auth_log (ts, username, mac, nas_ip, result, reason, profile) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), username, normalize_mac(mac), nas_ip, result, reason, profile),
            )

    def recent_auth(self, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM auth_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
