"""Data-plane authentication.

Session 12 finding A1/A2: after the Modal migration the gateway answers on
a public URL with no front door, so anyone with the URL can drive /v1/chat,
/v1/vision, /v1/embed, ... and read /v1/status, /v1/providers, ... . That
breaks invariant 2 (every action must be checked against the actual user)
and feeds invariant 8 (unbounded cost).

The control plane (/v1/control/*) and the channel WebSocket already gate on
the per-installation token. This module adds the missing gate in front of
the *data* plane: a bearer API key, delivered as its own secret, required by
every data-plane route.

Configuration:
  GLC_GATEWAY_API_KEY   the shared data-plane key (set in the Modal Secret).
  GLC_REQUIRE_AUTH      "0" disables the gate (local dev only). Default on.

If auth is required but no key is configured, the gate fails closed with 503
rather than silently allowing traffic.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException


def _configured_key() -> str | None:
    key = os.getenv("GLC_GATEWAY_API_KEY", "").strip()
    return key or None


def auth_required() -> bool:
    return os.getenv("GLC_REQUIRE_AUTH", "1").strip() != "0"


async def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: reject any data-plane request lacking the gateway
    API key. Applied at include_router time in glc.main so every data-plane
    route inherits it."""
    if not auth_required():
        return
    expected = _configured_key()
    if expected is None:
        # Fail closed: an unset key on a public deployment must not mean
        # "open to everyone".
        raise HTTPException(
            503,
            "gateway API key not configured; set GLC_GATEWAY_API_KEY "
            "(or GLC_REQUIRE_AUTH=0 for local dev)",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <api_key>)")
    presented = authorization.removeprefix("Bearer ").strip()
    # Constant-time compare so a caller cannot learn the key byte-by-byte.
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "invalid gateway API key")
