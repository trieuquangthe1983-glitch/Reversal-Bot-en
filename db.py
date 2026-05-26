"""SQLite persistence for the license server.

3 tables — same conceptual model as the bot's licensing tables, but here
the server is the source of truth.
"""
from __future__ import annotations
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("LICENSE_DB_PATH",
                         str(Path(os.getenv("LICENSE_STATE_DIR", "state")) / "licenses.db")))

SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tier TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    customer_email TEXT,                       -- optional, set if you ask
    payment_tx_hash TEXT,
    token TEXT UNIQUE,                         -- signed token string
    issued_at TEXT NOT NULL,
    activated_at TEXT,                         -- set when client first activates
    expires_at TEXT,                           -- NULL = lifetime
    last_heartbeat_at TEXT,
    revoked_at TEXT,
    revoke_reason TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_lic_machine ON licenses(machine_id);
CREATE INDEX IF NOT EXISTS idx_lic_tx ON licenses(payment_tx_hash);
CREATE INDEX IF NOT EXISTS idx_lic_active ON licenses(activated_at, expires_at);

CREATE TABLE IF NOT EXISTS payment_proofs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT UNIQUE NOT NULL,
    from_address TEXT,
    to_address TEXT,
    amount_usdt REAL,
    matched_tier TEXT,
    block_number INTEGER,
    confirmations INTEGER,
    verified_at TEXT NOT NULL,
    consumed_by_license_id INTEGER REFERENCES licenses(id),
    raw_receipt_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_proofs_tier ON payment_proofs(matched_tier);

CREATE TABLE IF NOT EXISTS activation_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip_address TEXT,
    machine_id TEXT,
    endpoint TEXT,                             -- verify-payment | activate | heartbeat
    tx_hash TEXT,
    success INTEGER NOT NULL DEFAULT 0,
    error_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_act_attempts_ts ON activation_attempts(ts);
CREATE INDEX IF NOT EXISTS idx_act_attempts_ip ON activation_attempts(ip_address, ts);
"""

_local = threading.local()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


def init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@contextmanager
def transaction():
    conn = get_db()
    conn.execute("BEGIN")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def close_thread_connection() -> None:
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
        _local.conn = None


# =========================================================================
# Repositories
# =========================================================================
def _row(r):
    return dict(r) if r else None


class LicenseRepo:
    @staticmethod
    def insert(tier: str, machine_id: str, expires_at: str | None,
               payment_tx_hash: str | None = None,
               customer_email: str | None = None) -> int:
        with transaction() as conn:
            conn.execute(
                "INSERT INTO licenses (tier, machine_id, customer_email, "
                "payment_tx_hash, issued_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (tier, machine_id.lower(), customer_email, payment_tx_hash,
                 _now(), expires_at),
            )
            return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    @staticmethod
    def set_token(license_id: int, token: str) -> None:
        with transaction() as conn:
            conn.execute("UPDATE licenses SET token = ? WHERE id = ?",
                         (token, license_id))

    @staticmethod
    def mark_activated(license_id: int) -> None:
        with transaction() as conn:
            conn.execute("UPDATE licenses SET activated_at = ? WHERE id = ?",
                         (_now(), license_id))

    @staticmethod
    def mark_heartbeat(license_id: int) -> None:
        with transaction() as conn:
            conn.execute("UPDATE licenses SET last_heartbeat_at = ? WHERE id = ?",
                         (_now(), license_id))

    @staticmethod
    def get(license_id: int) -> dict | None:
        return _row(get_db().execute(
            "SELECT * FROM licenses WHERE id = ?", (license_id,)
        ).fetchone())

    @staticmethod
    def get_by_token(token: str) -> dict | None:
        return _row(get_db().execute(
            "SELECT * FROM licenses WHERE token = ?", (token,)
        ).fetchone())

    @staticmethod
    def get_active_for_machine(machine_id: str) -> dict | None:
        return _row(get_db().execute(
            "SELECT * FROM licenses WHERE machine_id = ? AND revoked_at IS NULL "
            "AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY id DESC LIMIT 1",
            (machine_id.lower(), _now()),
        ).fetchone())

    @staticmethod
    def has_used_trial(machine_id: str) -> bool:
        return get_db().execute(
            "SELECT 1 FROM licenses WHERE machine_id = ? AND tier = 'trial' LIMIT 1",
            (machine_id.lower(),),
        ).fetchone() is not None

    @staticmethod
    def revoke(license_id: int, reason: str) -> None:
        with transaction() as conn:
            conn.execute(
                "UPDATE licenses SET revoked_at = ?, revoke_reason = ? WHERE id = ?",
                (_now(), reason, license_id),
            )

    @staticmethod
    def list_all(limit: int = 200) -> list[dict]:
        rows = get_db().execute(
            "SELECT id, tier, machine_id, customer_email, payment_tx_hash, "
            "issued_at, activated_at, expires_at, last_heartbeat_at, "
            "revoked_at, revoke_reason FROM licenses ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


class PaymentProofRepo:
    @staticmethod
    def get_by_tx(tx_hash: str) -> dict | None:
        return _row(get_db().execute(
            "SELECT * FROM payment_proofs WHERE tx_hash = ?",
            (tx_hash.lower(),)
        ).fetchone())

    @staticmethod
    def record(tx_hash: str, from_address: str, to_address: str,
               amount_usdt: float, matched_tier: str | None,
               block_number: int, confirmations: int,
               raw_receipt: dict | None = None) -> int:
        with transaction() as conn:
            conn.execute(
                "INSERT INTO payment_proofs (tx_hash, from_address, to_address, "
                "amount_usdt, matched_tier, block_number, confirmations, "
                "verified_at, raw_receipt_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tx_hash.lower(), from_address.lower(), to_address.lower(),
                 amount_usdt, matched_tier, block_number, confirmations,
                 _now(), json.dumps(raw_receipt or {})),
            )
            return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    @staticmethod
    def mark_consumed(tx_hash: str, license_id: int) -> None:
        with transaction() as conn:
            conn.execute(
                "UPDATE payment_proofs SET consumed_by_license_id = ? WHERE tx_hash = ?",
                (license_id, tx_hash.lower()),
            )


class ActivationAttemptRepo:
    @staticmethod
    def record(ip: str | None, machine_id: str | None, endpoint: str,
               tx_hash: str | None, success: bool,
               error_reason: str = "") -> int:
        with transaction() as conn:
            conn.execute(
                "INSERT INTO activation_attempts (ts, ip_address, machine_id, "
                "endpoint, tx_hash, success, error_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_now(), ip, machine_id, endpoint, tx_hash,
                 int(bool(success)), error_reason),
            )
            return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    @staticmethod
    def count_recent_failures(ip: str, minutes: int = 60) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        r = get_db().execute(
            "SELECT COUNT(*) AS n FROM activation_attempts "
            "WHERE ip_address = ? AND success = 0 AND ts >= ?",
            (ip, cutoff),
        ).fetchone()
        return int(r["n"]) if r else 0
