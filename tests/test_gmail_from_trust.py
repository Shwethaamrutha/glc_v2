"""Part 2 bug: Gmail From-header parsing must not resolve an ambiguous /
multi-sender header to a single (trusted) address.

_extract_email feeds both trust classification and the allowlist, so a header
that names the attacker as a co-sender must never collapse to the owner's
address. Breaks invariant 2. The fix uses stdlib getaddresses and requires
exactly one address.
"""

from __future__ import annotations

import pytest

from glc.channels.catalogue.gmail.adapter import Adapter


@pytest.fixture
def adapter():
    return Adapter(config={"mock": object()})


def test_single_sender_resolves(adapter):
    assert adapter._extract_email("Owner <owner@example.com>") == "owner@example.com"
    assert adapter._extract_email("owner@example.com") == "owner@example.com"


def test_multi_sender_is_not_resolved_to_first(adapter):
    # The message is co-sent by the attacker; must NOT resolve to the owner.
    assert adapter._extract_email("Owner <owner@example.com>, <attacker@evil.com>") == ""


def test_comma_list_is_rejected(adapter):
    assert adapter._extract_email("owner@example.com, attacker@evil.com") == ""


def test_empty_header(adapter):
    assert adapter._extract_email("") == ""


def test_quoted_local_resolves_to_real_addr(adapter):
    # '"owner@example.com" <attacker@evil.com>' — the real addr-spec is the
    # attacker's; the display text is not an address. Must be the real one.
    assert adapter._extract_email('"owner@example.com" <attacker@evil.com>') == "attacker@evil.com"
