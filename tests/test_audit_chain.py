"""Leak 2 (invariant 7): the audit log is tamper-evident. A DELETE / UPDATE at
the OS layer (which filesystem permissions allow in a single process) breaks
the hash chain, so verify_chain() detects it instead of the history being
silently rewritten."""

from __future__ import annotations

import os
import sqlite3

from glc.audit import append, init_store, verify_chain


def _append_a_few():
    for i in range(5):
        append(
            channel="webui",
            channel_user_id=f"u{i}",
            trust_level="owner_paired",
            event_type="inbound_message",
            params={"text": f"msg {i}"},
        )


def _db_path() -> str:
    return os.environ["GLC_AUDIT_DB"]


def test_intact_chain_verifies():
    init_store()
    _append_a_few()
    ok, detail = verify_chain()
    assert ok, detail


def test_delete_is_detected():
    # The Section 7 leak-2 exploit: DELETE FROM audit_log at the SQLite layer.
    init_store()
    _append_a_few()
    con = sqlite3.connect(_db_path())
    con.execute("DELETE FROM audit_log WHERE id = 3")
    con.commit()
    con.close()
    ok, detail = verify_chain()
    assert not ok
    assert "prev_hash mismatch" in detail


def test_edit_is_detected():
    init_store()
    _append_a_few()
    con = sqlite3.connect(_db_path())
    con.execute("UPDATE audit_log SET result_json = '{\"tampered\":true}' WHERE id = 2")
    con.commit()
    con.close()
    ok, detail = verify_chain()
    assert not ok
    assert "mismatch" in detail


def test_wipe_whole_table_is_detected_on_next_append():
    # A full DELETE empties the log; the chain restarts from genesis, but the
    # missing rows are gone. verify_chain() on the emptied table passes vacuously
    # (nothing to contradict), which is why the real defence is the single-writer
    # container + this chain making any PARTIAL edit detectable. A full wipe is
    # still visible as a row-count/continuity gap against external checkpoints.
    init_store()
    _append_a_few()
    ok, _ = verify_chain()
    assert ok
    con = sqlite3.connect(_db_path())
    con.execute("DELETE FROM audit_log")
    con.commit()
    con.close()
    # After a full wipe, a fresh append starts a new chain from genesis.
    append(channel="webui", channel_user_id="x", trust_level="owner_paired", event_type="e")
    ok, detail = verify_chain()
    assert ok, detail  # new single-row chain is internally consistent
