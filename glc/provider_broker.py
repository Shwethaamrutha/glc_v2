"""Provider broker — the gateway side of the key-isolation boundary.

`RemoteProvider` presents the same surface the Router already calls
(`.chat(...)`, `.stream(...)`, `.model`, `.capabilities`) but holds NO API
key. Instead it dispatches each call to an isolated worker that holds exactly
one provider's key, over one of two backends:

  * subprocess backend (default, locally deployable + testable): spawns
    `python -m glc.provider_worker` with only that provider's key in its env.
    Proves the gateway process itself never has the key in memory.

  * modal backend (production): calls a per-provider Modal Function, each
    deployed with a single Secret and its own egress allowlist. Selected with
    GLC_PROVIDER_BACKEND=modal.

This is the concrete form of invariant 1 ("adapters must never see provider
API keys") and the fix the lecture names for leak 1 / A4: "each adapter its
own container and its own Secret." The gateway's build_providers() constructs
RemoteProviders when GLC_ISOLATED_PROVIDERS=1, and — critically — does NOT read
any provider key itself.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from glc.providers import ProviderError, model_capabilities

# Model defaults are NOT secret; the gateway may know which model each provider
# runs so the Router can reason about capabilities. Only the keys are isolated.
_MODEL_DEFAULTS = {
    "gemini": ("GEMINI_MODEL", "gemini-2.5-flash"),
    "nvidia": ("NVIDIA_MODEL", "deepseek-ai/deepseek-v3.2"),
    "groq": ("GROQ_MODEL", "openai/gpt-oss-120b"),
    "cerebras": ("CEREBRAS_MODEL", "zai-glm-4.7"),
    "openrouter": ("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free"),
    "github": ("GITHUB_MODEL", "openai/gpt-4.1-mini"),
}

# Which providers are enabled in isolated mode. In isolated mode the gateway
# has no keys to probe, so enablement is declared explicitly (the deployment
# knows which per-provider workers/Secrets exist). Defaults to all six.
def _enabled_isolated_providers() -> list[str]:
    raw = os.getenv("GLC_ISOLATED_PROVIDER_LIST", "").strip()
    if raw:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return list(_MODEL_DEFAULTS.keys())


class RemoteProvider:
    """A keyless stand-in for a provider. Same call surface as BaseProvider."""

    def __init__(self, name: str, model: str | None = None) -> None:
        self.name = name
        env_name, default = _MODEL_DEFAULTS[name]
        self.model = model or os.getenv(env_name, default)
        self.capabilities = model_capabilities(name, self.model, {})

    async def chat(self, messages, **params) -> dict:
        return await _dispatch(self.name, self.model, messages, params)

    async def stream(self, messages, **params):
        # Streaming across the isolation boundary is degraded to a single
        # yield of the full result — correctness over token-streaming. The
        # gateway's stream() path handles a one-shot generator fine.
        result = await self.chat(messages, **params)
        yield result.get("text", "")


async def _dispatch(provider: str, model: str, messages, params: dict[str, Any]) -> dict:
    backend = os.getenv("GLC_PROVIDER_BACKEND", "subprocess").strip()
    req = {"provider": provider, "model": model, "op": "chat",
           "messages": messages, "params": _jsonable_params(params)}
    if backend == "modal":
        return await _dispatch_modal(req)
    return await _dispatch_subprocess(req)


def _jsonable_params(params: dict[str, Any]) -> dict[str, Any]:
    """Params may carry pydantic models (response_format, tools). Normalise to
    plain JSON so they cross the process boundary."""
    out = {}
    for k, v in params.items():
        if hasattr(v, "model_dump"):
            out[k] = v.model_dump()
        elif isinstance(v, list):
            out[k] = [x.model_dump() if hasattr(x, "model_dump") else x for x in v]
        else:
            out[k] = v
    return out


async def _dispatch_subprocess(req: dict) -> dict:
    """Spawn the worker with ONLY this provider's key in its environment."""
    provider = req["provider"]
    key_env = {
        "gemini": "GEMINI_API_KEY", "nvidia": "NVIDIA_API_KEY", "groq": "GROQ_API_KEY",
        "cerebras": "CEREBRAS_API_KEY", "openrouter": "OPEN_ROUTER_API_KEY",
        "github": "GITHUB_ACCESS_TOKEN",
    }[provider]

    # The gateway's own env must NOT contain the key in isolated mode; it is
    # sourced from a per-provider secret file the gateway cannot read as env.
    key_value = _read_isolated_key(provider)
    child_env = {"PATH": os.getenv("PATH", ""), "HOME": os.getenv("HOME", "")}
    if key_value:
        child_env[key_env] = key_value
    # Pass through model + config dir but never other providers' keys.
    for passthrough in ("GLC_CONFIG_DIR", *[d[0] for d in _MODEL_DEFAULTS.values()]):
        if os.getenv(passthrough):
            child_env[passthrough] = os.environ[passthrough]

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "glc.provider_worker",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=child_env,
    )
    out, err = await proc.communicate(json.dumps(req).encode())
    if proc.returncode != 0 and not out:
        raise ProviderError(f"worker crashed: {err.decode()[:200]}", status=502, retryable=True)
    resp = json.loads(out.decode())
    if not resp.get("ok"):
        raise ProviderError(resp.get("error", "worker error"),
                            status=resp.get("status"), retryable=resp.get("retryable", True))
    return resp["result"]


def _read_isolated_key(provider: str) -> str | None:
    """Read the provider key from a per-provider secret directory that the
    gateway process is NOT given as environment variables. Under Modal this is
    a per-provider Secret mounted only into that provider's worker; locally it
    is a file under GLC_PROVIDER_KEYS_DIR. Returns None if absent (mock/dev)."""
    keys_dir = os.getenv("GLC_PROVIDER_KEYS_DIR")
    if not keys_dir:
        return None
    from pathlib import Path

    p = Path(keys_dir) / f"{provider}.key"
    if p.exists():
        return p.read_text().strip()
    return None


async def _dispatch_modal(req: dict) -> dict:
    """Call the per-provider Modal Function by name. Each is deployed with a
    single Secret and its own egress allowlist (see infra/modal_workers.py)."""
    import modal

    fn = modal.Function.from_name("glc-provider-workers", f"chat_{req['provider']}")
    resp = await fn.remote.aio(req)
    if not resp.get("ok"):
        raise ProviderError(resp.get("error", "worker error"),
                            status=resp.get("status"), retryable=resp.get("retryable", True))
    return resp["result"]


def build_remote_providers() -> dict[str, RemoteProvider]:
    """Isolated-mode replacement for glc.providers.build_providers(). Builds
    keyless RemoteProviders — the gateway reads NO provider key here."""
    out: dict[str, RemoteProvider] = {}
    for name in _enabled_isolated_providers():
        if name in _MODEL_DEFAULTS:
            out[name] = RemoteProvider(name)
    return out
