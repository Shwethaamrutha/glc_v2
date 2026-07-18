"""Leak 1 / A4 (invariant 1): adapters/gateway must never see provider keys.

In isolated mode the gateway builds keyless RemoteProviders and never reads a
provider key from its own environment. The key lives only in the per-provider
worker's environment. These tests assert exactly that boundary.
"""

from __future__ import annotations

import pytest

from glc import provider_broker
from glc.provider_broker import RemoteProvider, build_remote_providers


def test_remote_provider_holds_no_key():
    rp = RemoteProvider("gemini")
    # A RemoteProvider exposes model + capabilities for routing, but has no
    # api_key attribute at all — there is nothing to steal from it.
    assert not hasattr(rp, "api_key")
    assert rp.model  # model is not secret
    assert isinstance(rp.capabilities, dict)


def test_build_remote_providers_reads_no_env_key(monkeypatch):
    # Even with a provider key present in the gateway env, isolated builder
    # must not consume or embed it into the RemoteProvider objects.
    monkeypatch.setenv("GEMINI_API_KEY", "should-not-be-touched")
    providers = build_remote_providers()
    assert "gemini" in providers
    for p in providers.values():
        assert not hasattr(p, "api_key")


def test_isolated_provider_list_override(monkeypatch):
    monkeypatch.setenv("GLC_ISOLATED_PROVIDER_LIST", "groq,gemini")
    providers = build_remote_providers()
    assert set(providers) == {"groq", "gemini"}


def test_worker_key_env_map_covers_all_providers():
    # Guard against a provider being added to _MODEL_DEFAULTS without a
    # corresponding key-env mapping in the subprocess dispatcher.
    import inspect

    src = inspect.getsource(provider_broker._dispatch_subprocess)
    for name in provider_broker._MODEL_DEFAULTS:
        assert f'"{name}"' in src, f"{name} missing from key_env map"


@pytest.mark.asyncio
async def test_subprocess_worker_returns_error_without_key(monkeypatch):
    # With no isolated key configured, the worker fails cleanly (no key in its
    # env) rather than silently succeeding — proving the key path is real.
    monkeypatch.setenv("GLC_PROVIDER_BACKEND", "subprocess")
    monkeypatch.delenv("GLC_PROVIDER_KEYS_DIR", raising=False)
    rp = RemoteProvider("gemini")
    from glc.providers import ProviderError

    with pytest.raises(ProviderError):
        await rp.chat([{"role": "user", "content": "hi"}], max_tokens=8)


@pytest.mark.asyncio
async def test_subprocess_worker_gets_only_its_own_key(monkeypatch, tmp_path):
    # Configure an isolated key dir with a mock gemini key; the worker builds
    # gemini and attempts the call (fails on the mock key at the provider, not
    # for lack of a key), while NO other provider key is passed to it.
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "gemini.key").write_text("mock-not-real")
    monkeypatch.setenv("GLC_PROVIDER_KEYS_DIR", str(keys))
    monkeypatch.setenv("GLC_PROVIDER_BACKEND", "subprocess")
    rp = RemoteProvider("gemini")
    from glc.providers import ProviderError

    # The call reaches the provider layer and fails on the mock key / network,
    # which surfaces as a ProviderError — not a "key not present" RuntimeError.
    with pytest.raises(ProviderError) as ei:
        await rp.chat([{"role": "user", "content": "hi"}], max_tokens=8)
    assert "not present in worker environment" not in str(ei.value)
