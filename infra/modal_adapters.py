"""Per-adapter isolated Sandbox Functions (weak-isolation / invariant 1).

Adapters are contributed third-party code that glc_v1 runs inside the gateway
process. This deploys each adapter as its OWN Modal Function with:

  * its own Secret — only that adapter's channel credential (e.g. Gmail OAuth
    client id/secret) is mounted, so it cannot read a sibling adapter's token;
  * its own egress allowlist — the adapter reaches only its channel's hosts
    (Gmail: googleapis.com / oauth2.googleapis.com) and nowhere else;
  * a minimal image with only that adapter's dependencies;
  * non-root, isolated PID/mount namespaces (gVisor), so it cannot signal the
    gateway's process or read its files.

The gateway (infra/modal_app.py) holds NO adapter secret. With
GLC_ISOLATED_ADAPTERS=1 + GLC_ADAPTER_BACKEND=modal it dispatches each
on_message / send to adapter_<name> by name via glc.adapter_broker.

Deploy:
    uv run modal deploy infra/modal_adapters.py

Create the per-adapter Secret first (mock values for the assignment):
    modal secret create glc-adapter-gmail \
        GMAIL_OAUTH_CLIENT_ID=mock-not-real \
        GMAIL_OAUTH_CLIENT_SECRET=mock-not-real \
        GMAIL_BOT_ADDRESS=bot@example.com
"""

from __future__ import annotations

from pathlib import Path

import modal

app = modal.App("glc-channel-adapters")

LOCAL_GLC = Path(__file__).parent.parent / "glc"

# Gmail needs the Google API client libraries; other adapters would add their
# own deps in their own image, so a Slack bug never pulls in Gmail's libraries.
_gmail_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        "httpx>=0.27", "pydantic>=2.6", "pyyaml>=6.0", "jsonschema>=4.21",
        "google-api-python-client>=2.0", "google-auth>=2.0",
    )
    .env({"GLC_EGRESS_ALLOWLIST": "gmail.googleapis.com,oauth2.googleapis.com,www.googleapis.com"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")  # local add last
)


@app.function(
    name="adapter_gmail",
    image=_gmail_image,
    secrets=[modal.Secret.from_name("glc-adapter-gmail")],
    min_containers=0,
    serialized=True,
)
async def adapter_gmail(req: dict) -> dict:
    # Runs inside the isolated Gmail container. Only Gmail's OAuth secret is in
    # env; no other adapter's token and no provider keys.
    from glc.adapter_worker import _run

    return await _run(req)
