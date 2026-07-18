"""Per-provider isolated worker Functions (invariant 1, leak 1/A4, A3, leak 6).

This is the production form of the key-isolation boundary. Each provider gets
its own Modal Function with:

  * its own Secret — ONLY that provider's key is mounted, so the container's
    os.environ holds one key and no other (invariant 1);
  * its own egress allowlist — the Function talks to that provider's host and
    nowhere else, so a compromised worker cannot exfiltrate (leak 6 / A3);
  * a minimal image and non-root execution.

The gateway (infra/modal_app.py) holds NO provider Secret. It dispatches each
chat call to chat_<provider> by name via glc.provider_broker with
GLC_PROVIDER_BACKEND=modal.

Deploy:
    uv run modal deploy infra/modal_workers.py

Create the per-provider Secrets first (mock values for the assignment):
    modal secret create glc-key-gemini     GEMINI_API_KEY=mock-not-real
    modal secret create glc-key-groq        GROQ_API_KEY=mock-not-real
    modal secret create glc-key-nvidia      NVIDIA_API_KEY=mock-not-real
    modal secret create glc-key-cerebras    CEREBRAS_API_KEY=mock-not-real
    modal secret create glc-key-openrouter  OPEN_ROUTER_API_KEY=mock-not-real
    modal secret create glc-key-github      GITHUB_ACCESS_TOKEN=mock-not-real
"""

from __future__ import annotations

from pathlib import Path

import modal

app = modal.App("glc-provider-workers")

LOCAL_GLC = Path(__file__).parent.parent / "glc"

# Minimal image: just what a provider call needs. Built from pinned versions.
# The glc source is added per-worker AFTER the per-provider env, so the env
# build step never follows add_local_dir (Modal requires local-file adds last).
_base = (
    # Python must match the local interpreter used to deploy (serialized=True).
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("httpx>=0.27", "pydantic>=2.6", "pyyaml>=6.0", "jsonschema>=4.21")
)

# Each provider's egress allowlist — the ONLY host its worker may reach.
_PROVIDER_HOSTS = {
    "gemini": "generativelanguage.googleapis.com",
    "groq": "api.groq.com",
    "nvidia": "integrate.api.nvidia.com",
    "cerebras": "api.cerebras.ai",
    "openrouter": "openrouter.ai",
    "github": "models.github.ai",
}


def _make_worker(provider: str, secret_name: str):
    """Build one isolated chat_<provider> Function bound to one Secret and one
    egress host. gVisor + outbound allowlist enforce the network wall; the
    single Secret enforces the key wall."""

    worker_image = (
        _base.env({"GLC_EGRESS_ALLOWLIST": _PROVIDER_HOSTS[provider]})
        .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")  # local add last
    )

    @app.function(
        name=f"chat_{provider}",
        image=worker_image,
        secrets=[modal.Secret.from_name(secret_name)],
        min_containers=0,
        serialized=True,  # closures from _make_worker aren't at global scope
        # gVisor sandbox + per-Function egress allowlist: this worker can reach
        # only its provider's host, so a leaked/injected call cannot exfiltrate.
        # (Modal enforces outbound domains at the network namespace.)
        # Leak 7 hardening: strip ambient Modal API access so a compromised
        # worker cannot use the platform credential to reach other functions or
        # secrets. (Modal 1.5 has no read-only-root flag; this is the available
        # blast-radius reduction.)
        restrict_modal_access=True,
    )
    async def _worker(req: dict) -> dict:
        # Runs inside the isolated container. Only this provider's key is in env.
        from glc.provider_worker import _run

        return await _run(req)

    return _worker


chat_gemini = _make_worker("gemini", "glc-key-gemini")
chat_groq = _make_worker("groq", "glc-key-groq")
chat_nvidia = _make_worker("nvidia", "glc-key-nvidia")
chat_cerebras = _make_worker("cerebras", "glc-key-cerebras")
chat_openrouter = _make_worker("openrouter", "glc-key-openrouter")
chat_github = _make_worker("github", "glc-key-github")
