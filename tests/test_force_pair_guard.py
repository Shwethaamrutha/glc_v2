"""Leak 3 (invariant 2): force_pair_owner must be denied inside the serving
gateway. Only a bootstrap process (GLC_ALLOW_FORCE_PAIR=1) may call it."""

from __future__ import annotations

import pytest

from glc.security.pairing import get_pairing_store


def test_force_pair_denied_without_bootstrap_flag(monkeypatch):
    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "0")
    store = get_pairing_store()
    with pytest.raises(PermissionError):
        store.force_pair_owner("telegram", "attacker-id", user_handle="me")


def test_force_pair_allowed_in_bootstrap(monkeypatch):
    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "1")
    store = get_pairing_store()
    rec = store.force_pair_owner("telegram", "owner-id", user_handle="owner")
    assert rec.trust_level == "owner_paired"
