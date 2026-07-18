"""Reproduction: trust_level forgery on the channel WebSocket path.

Run from a fresh checkout:
    uv run python repro_trust_level_forgery.py

WHAT IT SHOWS
-------------
ChannelMessage.trust_level is a field the client (the channel adapter) fills
in on the envelope. The gateway's WS handler (glc/routes/channels.py) consumes
env.trust_level verbatim for its audit record — and it is the field the policy
engine keys on (trust_level == 'owner_paired' -> default allow). The gateway
never re-derives trust from the pairing store via
glc.security.trust_level.classify().

So a sender whose REAL trust is 'user_paired' (or 'untrusted') can declare
'owner_paired' and the gateway attributes owner privilege to the message.
That breaks invariant 2: "every action must be checked against the actual
user, tenant, and final arguments" — here the principal's privilege is taken
from a self-declared field instead of the server's own record.

This is NOT leak 9 (that is env.channel != route, a different field). It is a
distinct, uncatalogued break.

EXPECTED OUTPUT
---------------
  real server-side trust : user_paired
  gateway recorded trust : owner_paired      <-- forged value accepted (BUG)

After the fix (glc/routes/channels.py re-derives via classify), the recorded
trust equals the real trust.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

os.environ.setdefault("GLC_CONFIG_DIR", tempfile.mkdtemp(prefix="glc-repro-"))
os.environ.setdefault("GLC_ENABLE_DOCS", "1")

from fastapi.testclient import TestClient  # noqa: E402

import glc.main as m  # noqa: E402
import glc.security.pairing as pairing  # noqa: E402
from glc.audit import query as audit_query  # noqa: E402
from glc.config import install_token_path  # noqa: E402
from glc.security.trust_level import classify  # noqa: E402


def main() -> None:
    with TestClient(m.app) as c:
        tok = install_token_path().read_text().strip()
        uid = "user1"

        # Pair uid as a NORMAL user (user_paired), and allowlist it so the
        # message is processed rather than dropped.
        pairing.get_pairing_store()  # ensure schema exists
        with pairing._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at)
                   VALUES (?,?,?,?,?)""",
                ("webui", uid, "u", "user_paired", 1.0),
            )
        import glc.config as cfg

        (cfg.CONFIG_DIR / "channels.yaml").write_text(
            f"channels:\n  webui:\n    enabled: true\n    allowed_senders: ['{uid}']\n"
        )

        real = classify("webui", uid)

        forged_envelope = {
            "channel": "webui",
            "channel_user_id": uid,
            "user_handle": "u",
            "text": "do owner-only things",
            "trust_level": "owner_paired",  # <-- FORGED (real trust is user_paired)
            "arrived_at": datetime.now(timezone.utc).isoformat(),
            "metadata": {},
        }

        with c.websocket_connect(
            "/v1/channels/webui", headers={"Authorization": f"Bearer {tok}"}
        ) as ws:
            ws.send_text(json.dumps(forged_envelope))
            ws.receive_text()

        inbound = [r for r in audit_query(limit=10) if r["event_type"] == "inbound_message"]
        recorded = inbound[0]["trust_level"] if inbound else "(message was dropped)"

        print(f"real server-side trust : {real}")
        print(f"gateway recorded trust : {recorded}")
        print()
        if real != "owner_paired" and recorded == "owner_paired":
            print("BUG REPRODUCED: the gateway accepted a forged owner_paired trust level.")
        elif recorded == real:
            print("FIXED: the gateway re-derived the real trust level, ignoring the forged value.")
        else:
            print(f"inconclusive (real={real}, recorded={recorded})")


if __name__ == "__main__":
    main()
