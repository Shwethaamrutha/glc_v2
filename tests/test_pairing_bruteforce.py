"""C6 (invariant 2): pairing-code confirmation is throttled so a 6-digit code
cannot be brute-forced."""

from __future__ import annotations

import pytest

from glc.security.pairing import (
    _MAX_CONFIRM_ATTEMPTS,
    PairingConfirmThrottled,
    get_pairing_store,
)


def test_repeated_wrong_codes_lock_out():
    store = get_pairing_store()
    # Feed wrong codes until the lockout trips.
    for _ in range(_MAX_CONFIRM_ATTEMPTS):
        assert store.confirm_code("000000") is None
    with pytest.raises(PairingConfirmThrottled):
        store.confirm_code("000001")


def test_valid_code_still_works_before_lockout():
    store = get_pairing_store()
    code, _ = store.issue_code("webui", "u1", "user", requested_trust_level="user_paired")
    # A couple of wrong guesses, then the right code (still under the limit).
    store.confirm_code("999999")
    rec = store.confirm_code(code)
    assert rec is not None
    assert rec.channel == "webui"
    assert rec.trust_level == "user_paired"
