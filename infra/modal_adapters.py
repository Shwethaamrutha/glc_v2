"""Per-adapter isolated Sandbox Functions (weak-isolation / invariant 1).

Adapters are contributed third-party code that glc_v1 runs inside the gateway
process. This deploys EACH adapter as its own Modal Function with:

  * its own Secret — only that adapter's channel credential(s) are mounted, so
    it cannot read a sibling adapter's token;
  * its own egress allowlist — the adapter reaches only its channel's hosts
    and nowhere else;
  * a minimal image with only that adapter's extra dependencies, so a bug in
    one adapter never pulls in another's libraries;
  * non-root, isolated PID/mount namespaces (gVisor), so it cannot signal the
    gateway's process or read its files.

The adapter set, per-adapter secrets, egress, and deps all come from the single
registry in glc.adapter_broker.ADAPTER_REGISTRY — the same source the gateway's
subprocess backend uses — so there is one source of truth.

The gateway (infra/modal_app.py) holds NO adapter secret. With
GLC_ISOLATED_ADAPTERS=1 + GLC_ADAPTER_BACKEND=modal it dispatches each
on_message / send to adapter_<name> by name via glc.adapter_broker.

Deploy:
    uv run modal deploy infra/modal_adapters.py

Create each per-adapter Secret first (mock values for the assignment), e.g.:
    modal secret create glc-adapter-telegram TELEGRAM_BOT_TOKEN=mock-not-real \
        TELEGRAM_OWNER_ID=0
The helper scripts/create_adapter_secrets.py generates all of them at once.
"""

from __future__ import annotations

import sys
from pathlib import Path

import modal

# Make the repo importable so we can read the single-source-of-truth registry.
sys.path.insert(0, str(Path(__file__).parent.parent))
from glc.adapter_broker import ADAPTER_REGISTRY  # noqa: E402

app = modal.App("glc-channel-adapters")

LOCAL_GLC = Path(__file__).parent.parent / "glc"
_BASE_PIP = ["httpx>=0.27", "pydantic>=2.6", "pyyaml>=6.0", "jsonschema>=4.21"]


def _make_adapter(name: str, cfg: dict):
    image = modal.Image.debian_slim(python_version="3.12").pip_install(*(_BASE_PIP + cfg["pip"]))
    if cfg["egress"]:
        image = image.env({"GLC_EGRESS_ALLOWLIST": cfg["egress"]})
    image = image.add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")  # local add last

    @app.function(
        name=f"adapter_{name}",
        image=image,
        secrets=[modal.Secret.from_name(f"glc-adapter-{name}")],
        min_containers=0,
        serialized=True,
        # Leak 7 hardening: strip ambient Modal API access so a compromised
        # adapter cannot use the platform credential to reach other functions or
        # secrets, on top of gVisor + per-adapter egress allowlist.
        restrict_modal_access=True,
    )
    async def _adapter(req: dict) -> dict:
        # Runs inside the isolated container. Only this adapter's secret is in
        # env; no other adapter's token and no provider keys.
        from glc.adapter_worker import _run

        return await _run(req)

    return _adapter


# Materialize one isolated Function per adapter from the registry.
_deployed = {name: _make_adapter(name, cfg) for name, cfg in ADAPTER_REGISTRY.items()}
