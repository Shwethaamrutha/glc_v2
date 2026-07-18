"""Leak 9 / C2 (cross-channel envelope spoofing) and C3 (WS token in query
string) on the WS /v1/channels/{name} route."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from websockets.exceptions import ConnectionClosed


def _envelope(channel: str, text: str = "hi") -> dict:
    return {
        "channel": channel,
        "channel_user_id": "u1",
        "user_handle": "u1",
        "text": text,
        "trust_level": "owner_paired",
        "arrived_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {},
    }


def test_ws_rejects_query_string_token(app_client: TestClient, install_token: str):
    # C3: the query-string token path is removed; only the header is accepted.
    try:
        with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
            ws.receive_text()
        raised = False
    except Exception:
        raised = True
    assert raised, "query-string token must not authenticate the WS"


def test_ws_accepts_header_token(app_client: TestClient, install_token: str):
    # Pair the sender as owner so it clears the allowlist and reaches the echo.
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("webui", "u1", user_handle="owner")
    with app_client.websocket_connect(
        "/v1/channels/webui",
        headers={"Authorization": f"Bearer {install_token}"},
    ) as ws:
        ws.send_text(json.dumps(_envelope("webui")))
        reply = json.loads(ws.receive_text())
        assert reply["channel"] == "webui"
        assert reply["text"].startswith("[glc echo]")


def test_ws_rejects_channel_mismatch(app_client: TestClient, install_token: str):
    # Leak 9: connect on /webui but declare channel="discord".
    with app_client.websocket_connect(
        "/v1/channels/webui",
        headers={"Authorization": f"Bearer {install_token}"},
    ) as ws:
        ws.send_text(json.dumps(_envelope("discord")))
        reply = json.loads(ws.receive_text())
        assert "does not match route" in reply.get("error", "")
        # The socket is closed right after the rejection.
        try:
            ws.receive_text()
        except (ConnectionClosed, Exception):
            pass
