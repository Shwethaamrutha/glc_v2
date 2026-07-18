"""Leak 10 (invariant 7/8): log_call() must reject impossible token counts so
the cost ledger cannot be poisoned into corrupting budget accounting."""

from __future__ import annotations

import pytest

from glc import db


def test_rejects_absurd_token_count():
    with pytest.raises(db.LedgerValidationError):
        db.log_call(provider="gemini", model="x", input_tokens=999_999_999, agent="victim")


def test_rejects_negative_tokens():
    with pytest.raises(db.LedgerValidationError):
        db.log_call(provider="gemini", model="x", output_tokens=-5, agent="victim")


def test_rejects_non_int():
    with pytest.raises(db.LedgerValidationError):
        db.log_call(provider="gemini", model="x", input_tokens="lots", agent="victim")


def test_accepts_reasonable_counts():
    # A normal call still logs fine and is queryable.
    db.init()
    db.log_call(provider="gemini", model="x", input_tokens=120, output_tokens=45, agent="ok")
    rows = db.recent(limit=5, provider="gemini")
    assert any(r["agent"] == "ok" for r in rows)


def test_signed_writer_valid_rows_verify():
    db.init()
    db.log_call(provider="gemini", model="x", input_tokens=100, output_tokens=20, agent="a")
    db.log_call(provider="groq", model="y", input_tokens=50, output_tokens=10, agent="b")
    ok, detail = db.verify_ledger()
    assert ok, detail


def test_signed_writer_detects_raw_sql_forgery():
    # The leak-10 exploit, done below the app layer: forge a row (or edit a
    # count) via raw SQLite with no signing key. verify_ledger must catch it.
    import sqlite3

    db.init()
    db.log_call(provider="gemini", model="x", input_tokens=100, output_tokens=20, agent="victim")
    con = sqlite3.connect(db._db_path())
    con.execute("UPDATE calls SET input_tokens=999999999 WHERE agent='victim'")
    con.commit()
    con.close()
    ok, detail = db.verify_ledger()
    assert not ok
    assert "signature mismatch" in detail


def test_signed_writer_detects_forged_insert():
    import sqlite3

    db.init()
    db.log_call(provider="gemini", model="x", input_tokens=100, output_tokens=20, agent="real")
    con = sqlite3.connect(db._db_path())
    # An attacker inserts a fabricated row with a made-up signature.
    con.execute(
        "INSERT INTO calls (ts, provider, model, input_tokens, output_tokens, call_role, agent, sig) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (1.0, "gemini", "x", 888888888, 0, "worker", "attacker", "deadbeef"),
    )
    con.commit()
    con.close()
    ok, detail = db.verify_ledger()
    assert not ok
