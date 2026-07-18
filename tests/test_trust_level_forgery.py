"""Part 2 bug: trust_level forgery on the channel WS / webhook paths.

ChannelMessage.trust_level is a client-supplied field. The gateway must
re-derive trust server-side from the pairing store (classify), never trust the
declared value — otherwise a sender escalates its own privilege by declaring
owner_paired. Breaks invariant 2 (every action checked against the ACTUAL
principal). Distinct from leak 9 (which is env.channel != route).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient

import glc.security.pairing as pairing


def _pair(channel: str, uid: str, trust: str) -> None:
    pairing.get_pairing_store()  # ensure schema
    with pairing._conn() as c:
        c.execute(
            """INSERT OR REPLACE INTO pairings
               (channel, channel_user_id, user_handle, trust_level, paired_at)
               VALUES (?,?,?,?,?)""",
            (channel, uid, "u", trust, 1.0),
        )


def _allowlist(uid: str) -> None:
    import glc.config as cfg

    (cfg.CONFIG_DIR / "channels.yaml").write_text(
        f"channels:\n  webui:\n    enabled: true\n    allowed_senders: ['{uid}']\n"
    )


def _envelope(uid: str, declared_trust: str) -> dict:
    return {
        "channel": "webui",
        "channel_user_id": uid,
        "user_handle": "u",
        "text": "x",
        "trust_level": declared_trust,
        "arrived_at": datetime.now(UTC).isoformat(),
        "metadata": {},
    }


def test_ws_rederives_trust_ignoring_declared(app_client: TestClient, install_token: str):
    uid = "user1"
    _pair("webui", uid, "user_paired")  # real trust
    _allowlist(uid)
    from glc.audit import query as audit_query

    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_envelope(uid, "owner_paired")))  # forged up
        ws.receive_text()

    inbound = [r for r in audit_query(limit=10) if r["event_type"] == "inbound_message"]
    assert inbound, "message should have been processed"
    # The forged owner_paired must have been overridden to the real user_paired.
    assert inbound[0]["trust_level"] == "user_paired"


def test_ws_unpaired_sender_is_untrusted_not_declared(app_client: TestClient, install_token: str):
    uid = "stranger"
    _allowlist(uid)  # allowlisted but NOT paired -> real trust is untrusted
    from glc.audit import query as audit_query

    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_envelope(uid, "owner_paired")))
        ws.receive_text()

    inbound = [r for r in audit_query(limit=10) if r["event_type"] == "inbound_message"]
    assert inbound
    assert inbound[0]["trust_level"] == "untrusted"
