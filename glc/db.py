"""V9-compatible per-call ledger. Same schema as llm_gatewayV9/db.py, but
the database lives under ~/.glc/ so the gateway is installable as a daemon
without writing into the source tree.

Note: this is the *worker call* ledger, used by /v1/cost/by_agent. The
audit log (every channel message, policy verdict, tool dispatch) is a
separate append-only store under glc/audit/store.py.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def _config_dir() -> Path:
    return Path(os.getenv("GLC_CONFIG_DIR", os.path.expanduser("~/.glc")))


def _db_path() -> str:
    # Honor GLC_CONFIG_DIR so the ledger persists on the Modal Volume.
    return os.getenv("GLC_GATEWAY_DB", str(_config_dir() / "gateway.sqlite"))


# Back-compat module attribute (some callers/tests read db.DB_PATH).
DB_PATH = _db_path()


def _ensure_parent() -> None:
    Path(_db_path()).parent.mkdir(parents=True, exist_ok=True)


# Leak 10: log_call() previously wrote whatever token counts the caller
# supplied, validating nothing, so a caller could poison the cost ledger with
# input_tokens=999_999_999 (or negatives) and corrupt every /v1/cost/by_agent
# and budget calculation built on it. Breaks invariant 8 (cost accounting is
# the basis of the hard spend limit) and invariant 7 (the ledger is a record).
#
# Two layers close this, matching the session's prescribed fix ("process
# separation plus a signed writer that the gateway holds"):
#   1. input validation — reject negative / non-int / absurd token counts, so
#      the documented in-process log_call() poison is rejected at the door;
#   2. a signed writer — each row carries an HMAC over its contents, keyed by a
#      secret only the gateway process holds (GLC_LEDGER_SIGNING_KEY). A row
#      forged via raw SQLite access (no key) fails verify_ledger(), so ledger
#      tampering is detectable even below the application layer.
_MAX_TOKENS_PER_CALL = 10_000_000


class LedgerValidationError(ValueError):
    """Raised when a cost-ledger write carries impossible token counts."""


def _signing_key() -> bytes:
    """The gateway-held key that signs ledger rows. Delivered as a Secret
    (GLC_LEDGER_SIGNING_KEY) in production; a stable per-DB fallback is derived
    for local/dev so signing is always on. Only code in the gateway process has
    this key — a raw-SQLite forger does not."""
    k = os.getenv("GLC_LEDGER_SIGNING_KEY", "").strip()
    if k:
        return k.encode()
    # Dev fallback: stable across a run, not committed anywhere.
    return hashlib.sha256(f"glc-ledger-dev::{_db_path()}".encode()).digest()


def _row_signature(fields: tuple) -> str:
    """HMAC-SHA256 over the canonical row tuple. Any change to a signed field
    (e.g. input_tokens forged via raw SQL) invalidates the signature."""
    msg = "\x1f".join("" if v is None else str(v) for v in fields).encode()
    return hmac.new(_signing_key(), msg, hashlib.sha256).hexdigest()


def _validate_counts(**counts: int) -> None:
    for field, value in counts.items():
        if value is None:
            continue
        if not isinstance(value, int) or isinstance(value, bool):
            raise LedgerValidationError(f"{field} must be an int, got {value!r}")
        if value < 0:
            raise LedgerValidationError(f"{field} must be non-negative, got {value}")
        if value > _MAX_TOKENS_PER_CALL:
            raise LedgerValidationError(
                f"{field}={value} exceeds per-call ceiling {_MAX_TOKENS_PER_CALL}"
            )


@contextmanager
def conn():
    _ensure_parent()
    c = sqlite3.connect(_db_path())
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init() -> None:
    with conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                cache_create_tokens INTEGER DEFAULT 0,
                cache_read_tokens INTEGER DEFAULT 0,
                latency_ms INTEGER DEFAULT 0,
                status TEXT,
                error TEXT,
                prompt_chars INTEGER DEFAULT 0,
                response_chars INTEGER DEFAULT 0,
                override TEXT,
                attempted TEXT,
                tool_calls INTEGER DEFAULT 0,
                reasoning_applied INTEGER DEFAULT 0,
                tool_dialect TEXT,
                call_role TEXT DEFAULT 'worker',
                router_decision TEXT,
                embed_dim INTEGER,
                agent TEXT,
                session TEXT,
                retries INTEGER DEFAULT 0,
                sig TEXT
            )"""
        )
        # Defensive migration: add the signature column to a pre-existing DB.
        cols = {r[1] for r in c.execute("PRAGMA table_info(calls)").fetchall()}
        if "sig" not in cols:
            c.execute("ALTER TABLE calls ADD COLUMN sig TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON calls(ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_prov_ts ON calls(provider, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_role_ts ON calls(call_role, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_ts ON calls(agent, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_session_ts ON calls(session, ts DESC)")


# The signed fields, in the exact order fed to _row_signature (must match
# between log_call() and verify_ledger()).
_SIGNED_FIELDS = (
    "ts", "provider", "model", "input_tokens", "output_tokens",
    "cache_create_tokens", "cache_read_tokens", "latency_ms", "status",
    "prompt_chars", "response_chars", "call_role", "agent", "session",
)


def log_call(
    provider,
    model,
    input_tokens=0,
    output_tokens=0,
    latency_ms=0,
    status="ok",
    error=None,
    prompt_chars=0,
    response_chars=0,
    override=None,
    attempted=None,
    cache_create_tokens=0,
    cache_read_tokens=0,
    tool_calls=0,
    reasoning_applied=False,
    tool_dialect=None,
    call_role="worker",
    router_decision=None,
    embed_dim=None,
    agent=None,
    session=None,
    retries=0,
) -> None:
    _validate_counts(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_create_tokens=cache_create_tokens,
        cache_read_tokens=cache_read_tokens,
    )
    ts = time.time()
    # Sign the row with the gateway-held key. The signed field values, in the
    # order declared by _SIGNED_FIELDS.
    sig = _row_signature((
        ts, provider, model, input_tokens, output_tokens,
        cache_create_tokens, cache_read_tokens, latency_ms, status,
        prompt_chars, response_chars, call_role, agent, session,
    ))
    with conn() as c:
        c.execute(
            """INSERT INTO calls (ts, provider, model, input_tokens, output_tokens,
                                  cache_create_tokens, cache_read_tokens,
                                  latency_ms, status, error, prompt_chars, response_chars,
                                  override, attempted, tool_calls, reasoning_applied, tool_dialect,
                                  call_role, router_decision, embed_dim,
                                  agent, session, retries, sig)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts,
                provider,
                model,
                input_tokens,
                output_tokens,
                cache_create_tokens,
                cache_read_tokens,
                latency_ms,
                status,
                error,
                prompt_chars,
                response_chars,
                override,
                attempted,
                tool_calls,
                1 if reasoning_applied else 0,
                tool_dialect,
                call_role,
                router_decision,
                embed_dim,
                agent,
                session,
                retries,
                sig,
            ),
        )


def by_agent(session=None, since=None):
    where = ["ts >= ?"]
    # Day-rollover fix: bucket by calendar day, not by 24h window.
    args = [since if since is not None else (time.time() - (time.time() % 86400))]
    if session:
        where.append("session=?")
        args.append(session)
    q = (
        "SELECT agent, provider, COUNT(*) AS calls, "
        "SUM(input_tokens) AS in_tok, SUM(output_tokens) AS out_tok, "
        "SUM(latency_ms) AS total_latency_ms, "
        "SUM(retries) AS total_retries, "
        "SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok, "
        "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors "
        "FROM calls WHERE " + " AND ".join(where) + " AND agent IS NOT NULL "
        "GROUP BY agent, provider"
    )
    with conn() as c:
        rows = c.execute(q, args).fetchall()
        out: dict[str, list[dict]] = {}
        for r in rows:
            out.setdefault(r["agent"], []).append(dict(r))
        return out


def recent(limit=100, provider=None, status=None):
    q = "SELECT * FROM calls"
    where, args = [], []
    if provider:
        where.append("provider=?")
        args.append(provider)
    if status:
        where.append("status=?")
        args.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def aggregate(call_role=None):
    now = time.time()
    day_start = now - (now % 86400)
    q = """SELECT provider,
                  COUNT(*) AS calls,
                  SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok_calls,
                  SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
                  SUM(input_tokens) AS in_tok,
                  SUM(output_tokens) AS out_tok,
                  SUM(cache_read_tokens) AS cache_reads,
                  SUM(cache_create_tokens) AS cache_creates,
                  SUM(tool_calls) AS tool_calls,
                  AVG(latency_ms) AS avg_latency,
                  MAX(ts) AS last_ts
             FROM calls WHERE ts >= ?"""
    args = [day_start]
    if call_role == "worker":
        q += " AND (call_role='worker' OR call_role IS NULL)"
    elif call_role == "router":
        q += " AND call_role LIKE 'router%'"
    elif call_role:
        q += " AND call_role=?"
        args.append(call_role)
    q += " GROUP BY provider"
    with conn() as c:
        rows = c.execute(q, args).fetchall()
        return {r["provider"]: dict(r) for r in rows}


def verify_ledger(limit: int | None = None) -> tuple[bool, str]:
    """Leak 10: recompute each row's HMAC and report the first row whose
    signature does not match — i.e. a row inserted or edited without the
    gateway's signing key (raw-SQLite poisoning). Returns (ok, detail).

    Rows with a NULL sig are pre-signing legacy rows and are reported as
    unsigned rather than forged."""
    q = "SELECT * FROM calls ORDER BY id ASC"
    if limit:
        q = f"SELECT * FROM (SELECT * FROM calls ORDER BY id DESC LIMIT {int(limit)}) ORDER BY id ASC"
    unsigned = 0
    with conn() as c:
        try:
            rows = c.execute(q).fetchall()
        except sqlite3.OperationalError:
            return True, "ledger empty"
    for r in rows:
        stored = r["sig"] if "sig" in r.keys() else None
        if not stored:
            unsigned += 1
            continue
        expected = _row_signature(tuple(r[f] for f in _SIGNED_FIELDS))
        if not hmac.compare_digest(stored, expected):
            return False, f"row id={r['id']}: signature mismatch (inserted/edited without the signing key)"
    detail = f"all signed rows valid ({len(rows) - unsigned} signed"
    if unsigned:
        detail += f", {unsigned} unsigned legacy"
    return True, detail + ")"
