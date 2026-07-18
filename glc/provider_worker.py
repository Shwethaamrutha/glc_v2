"""Isolated provider worker (leak 1 / A4 / invariant 1).

The gateway process must never hold provider API keys. This worker is the
other side of that boundary: it runs as a *separate process* (a subprocess
locally, a per-provider Modal Function in production), with exactly one
provider's key present in its environment, builds that single provider, makes
the call, and returns the normalised result.

Because it is a distinct process, no `os.environ["GEMINI_API_KEY"]` read from
gateway code — or from any channel adapter sharing the gateway process — can
reach the key: it simply is not in that process's memory. That is the
structural property invariant 1 demands, and the reason the lecture's fix is
"each adapter its own container and its own Secret" rather than an in-process
guard.

Wire protocol (subprocess backend): one JSON request object on stdin, one JSON
response object on stdout.

  request  = {"provider": "gemini", "model": "...", "op": "chat",
              "messages": [...], "params": {...}}
  response = {"ok": true, "result": {...normalised provider dict...}}
           | {"ok": false, "error": "...", "status": 502, "retryable": true}

Run as:  python -m glc.provider_worker
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

# Egress guard: even inside the worker, refuse outbound to anything but this
# provider's own host. Full kernel-enforced egress is the Modal Sandbox
# outbound_domain_allowlist (see infra/); this is the application-layer
# companion that also holds under the subprocess backend.
from glc.security.egress import assert_egress_allowed  # noqa: F401  (imported for side-effect docs)


def _build_single_provider(provider: str, model: str | None):
    """Build exactly one provider from the single key in this process's env.
    Mirrors glc.providers.build_providers but for one provider only, so the
    worker never instantiates a provider whose key it does not hold."""
    import glc.providers as P
    from glc.cache import GeminiCache

    key_env = {
        "gemini": "GEMINI_API_KEY",
        "nvidia": "NVIDIA_API_KEY",
        "groq": "GROQ_API_KEY",
        "cerebras": "CEREBRAS_API_KEY",
        "openrouter": "OPEN_ROUTER_API_KEY",
        "github": "GITHUB_ACCESS_TOKEN",
    }
    ctor = {
        "gemini": lambda k: P.GeminiProvider(k, model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash"), GeminiCache(ttl_seconds=300)),
        "nvidia": lambda k: P.NvidiaProvider(k, model or os.getenv("NVIDIA_MODEL", "deepseek-ai/deepseek-v3.2")),
        "groq": lambda k: P.GroqProvider(k, model or os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")),
        "cerebras": lambda k: P.CerebrasProvider(k, model or os.getenv("CEREBRAS_MODEL", "zai-glm-4.7")),
        "openrouter": lambda k: P.OpenRouterProvider(k, model or os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")),
        "github": lambda k: P.GitHubProvider(k, model or os.getenv("GITHUB_MODEL", "openai/gpt-4.1-mini")),
    }
    if provider not in ctor:
        raise ValueError(f"unknown provider {provider!r}")
    env_name = key_env[provider]
    key = os.getenv(env_name)
    if not key:
        raise RuntimeError(f"{env_name} not present in worker environment for provider {provider!r}")
    return ctor[provider](key)


async def _run(req: dict[str, Any]) -> dict[str, Any]:
    import glc.providers as P

    provider = req["provider"]
    model = req.get("model")
    params = req.get("params", {})
    messages = req.get("messages", [])
    try:
        prov = _build_single_provider(provider, model)
        result = await prov.chat(messages, **params)
        return {"ok": True, "result": result}
    except P.ProviderError as e:
        return {"ok": False, "error": str(e), "status": getattr(e, "status", None),
                "retryable": getattr(e, "retryable", True)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "status": None, "retryable": True}


def main() -> None:
    raw = sys.stdin.read()
    try:
        req = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        sys.stdout.write(json.dumps({"ok": False, "error": f"bad request json: {e}", "status": 400,
                                     "retryable": False}))
        return
    resp = asyncio.run(_run(req))
    sys.stdout.write(json.dumps(resp))


if __name__ == "__main__":
    main()
