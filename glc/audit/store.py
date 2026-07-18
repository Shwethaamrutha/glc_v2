"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# Genesis hash for the first row of the tamper-evident chain (leak 2).
_GENESIS = "0" * 64


def _row_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Deterministic hash over (prev_hash + canonical row payload). Chaining
    prev_hash in means editing or deleting any earlier row invalidates every
    row after it, so tampering is detectable even with raw file access."""
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        # Defensive migration for databases created under schema v1 (no chain
        # columns). ADD COLUMN is a no-op guarded by a column check.
        cols = {r[1] for r in c.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "prev_hash" not in cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "row_hash" not in cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT")


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        ts = time.time()
        params_json = _jsonify(params)
        result_json = _jsonify(result)
        with _conn() as c:
            # Chain to the most recent row's hash (leak 2). One writer at a time
            # (A6: single audit container) keeps this read-then-write atomic.
            row = c.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = (row["row_hash"] if row and row["row_hash"] else _GENESIS)
            payload = {
                "ts": ts, "session_id": session_id, "channel": channel,
                "channel_user_id": channel_user_id, "trust_level": trust_level,
                "event_type": event_type, "tool": tool, "policy_verdict": policy_verdict,
                "params_json": params_json, "result_json": result_json,
            }
            row_hash = _row_hash(prev_hash, payload)
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash, row_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash, row_hash,
                ),
            )
            return int(cur.lastrowid or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)


def verify_chain() -> tuple[bool, str]:
    """Leak 2: recompute the hash chain and report the first break. A DELETE,
    UPDATE, or spliced INSERT anywhere in the log breaks the chain here, so the
    tampering the filesystem permits is no longer silent (invariant 7).

    Returns (ok, detail). ok=True means the log is intact."""
    prev_hash = _GENESIS
    with _conn() as c:
        rows = c.execute(
            """SELECT id, ts, session_id, channel, channel_user_id, trust_level,
                      event_type, tool, policy_verdict, params_json, result_json,
                      prev_hash, row_hash
               FROM audit_log ORDER BY id ASC"""
        ).fetchall()
    for r in rows:
        if r["prev_hash"] != prev_hash:
            return False, f"row id={r['id']}: prev_hash mismatch (a prior row was deleted or edited)"
        payload = {
            "ts": r["ts"], "session_id": r["session_id"], "channel": r["channel"],
            "channel_user_id": r["channel_user_id"], "trust_level": r["trust_level"],
            "event_type": r["event_type"], "tool": r["tool"], "policy_verdict": r["policy_verdict"],
            "params_json": r["params_json"], "result_json": r["result_json"],
        }
        expected = _row_hash(prev_hash, payload)
        if r["row_hash"] != expected:
            return False, f"row id={r['id']}: row_hash mismatch (this row was edited)"
        prev_hash = r["row_hash"]
    return True, f"chain intact ({len(rows)} rows)"
