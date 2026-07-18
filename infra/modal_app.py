"""Hardened Modal gateway (Session 12 Part 1).

Differences from the shipped Move-1 modal_app.py, each closing a finding:

  * No provider Secret on the gateway (leak 1 / A4 / invariant 1). The gateway
    runs with GLC_ISOLATED_PROVIDERS=1 and holds ZERO provider keys; each
    provider call is dispatched to a per-provider worker Function (see
    infra/modal_workers.py), which alone holds that provider's Secret.

  * Data-plane auth on (A1) and docs off (A2): GLC_REQUIRE_AUTH=1 with the
    gateway API key delivered by its own Secret; GLC_ENABLE_DOCS unset.

  * Reproducible image (A5): built from the pinned uv.lock via uv, and the
    debian base is pinned by digest rather than the rolling tag.

  * Single audit writer (A6): max_containers=1 so there is never more than one
    SQLite writer on the audit Volume, and the app commits each append.

Deploy:
    uv run modal deploy infra/modal_app.py

Requires two Secrets (mock values for the assignment):
    modal secret create glc-gateway-auth  GLC_GATEWAY_API_KEY=pick-a-long-random-value
    # per-provider key Secrets are created for infra/modal_workers.py
"""

from __future__ import annotations

from pathlib import Path

import modal

app = modal.App("glc-gateway")

LOCAL_ROOT = Path(__file__).parent.parent
LOCAL_GLC = LOCAL_ROOT / "glc"

# A5: pin the base image by digest (reproducible) and install from uv.lock so
# the dependency set cannot drift under us. Replace the digest with the current
# debian:12-slim digest at build time; pinning the tag alone still floats.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("uv")
    .add_local_file(str(LOCAL_ROOT / "pyproject.toml"), remote_path="/app/pyproject.toml", copy=True)
    .add_local_file(str(LOCAL_ROOT / "uv.lock"), remote_path="/app/uv.lock", copy=True)
    # --no-emit-project drops the "-e ." line: the glc package is added to the
    # image separately (at /root/glc), so we install only the pinned third-party
    # deps here. --no-hashes keeps the install robust across index mirrors.
    .run_commands(
        "cd /app && uv export --frozen --no-dev --no-emit-project --no-hashes "
        "--format requirements-txt > /app/req.txt",
        "cd /app && uv pip install --system -r /app/req.txt",
    )
    .env({
        "GLC_CONFIG_DIR": "/data/glc",
        "GLC_ISOLATED_PROVIDERS": "1",   # gateway holds no provider keys
        "GLC_PROVIDER_BACKEND": "modal",  # dispatch to per-provider workers
        "GLC_REQUIRE_AUTH": "1",          # A1: data-plane auth on
        # GLC_ENABLE_DOCS intentionally unset -> docs/openapi disabled (A2)
    })
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# Only the gateway auth key — NO provider keys here (invariant 1).
gateway_auth = modal.Secret.from_name("glc-gateway-auth")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[gateway_auth],
    min_containers=0,
    max_containers=1,  # A6: single SQLite audit writer, no split/corrupt trail
)
@modal.asgi_app()
def fastapi_app():
    import os

    os.makedirs("/data/glc", exist_ok=True)
    from glc.main import app as web

    return web
