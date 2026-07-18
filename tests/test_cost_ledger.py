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
    db.log_call(provider="gemini", model="x", input_tokens=120, output_tokens=45, agent="ok")
    rows = db.recent(limit=5, provider="gemini")
    assert any(r["agent"] == "ok" for r in rows)
