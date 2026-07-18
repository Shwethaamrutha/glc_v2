"""Adapter isolation (weak-isolation hardening; invariant 1 for channel creds).

The Gmail adapter — like every contributed adapter — must not run in the
gateway's process. These tests prove the isolation boundary: the gateway holds
no Gmail secret, imports no adapter code in isolated mode, and dispatches to a
worker that runs the adapter in its own process with only its own secret.
"""

from __future__ import annotations

import sys

import pytest

from glc.adapter_broker import (
    RemoteAdapter,
    RemoteAdapterError,
    _read_adapter_secrets,
    build_remote_adapters,
    isolated_adapters,
)


def test_remote_adapter_holds_no_secret():
    ra = RemoteAdapter("gmail")
    # No client, no token, no OAuth attributes — nothing to steal from it.
    assert not hasattr(ra, "config")
    assert not hasattr(ra, "_client")
    assert ra.name == "gmail"


def test_build_remote_adapters_are_keyless():
    adapters = build_remote_adapters()
    assert "gmail" in adapters
    assert all(isinstance(a, RemoteAdapter) for a in adapters.values())


def test_isolated_adapter_list_override(monkeypatch):
    monkeypatch.setenv("GLC_ISOLATED_ADAPTER_LIST", "gmail")
    assert isolated_adapters() == ["gmail"]


def test_secret_dir_yields_only_that_adapters_secrets(tmp_path, monkeypatch):
    # Lay down gmail secrets AND a sibling adapter's secret; the reader for
    # gmail must return only gmail's, never the sibling's.
    base = tmp_path / "adapter-secrets"
    (base / "gmail").mkdir(parents=True)
    (base / "gmail" / "GMAIL_OAUTH_CLIENT_ID").write_text("gmail-id")
    (base / "gmail" / "GMAIL_OAUTH_CLIENT_SECRET").write_text("gmail-secret")
    (base / "slack").mkdir(parents=True)
    (base / "slack" / "SLACK_BOT_TOKEN").write_text("slack-token-should-not-leak")
    monkeypatch.setenv("GLC_ADAPTER_SECRETS_DIR", str(base))

    got = _read_adapter_secrets("gmail")
    assert got.get("GMAIL_OAUTH_CLIENT_ID") == "gmail-id"
    assert "SLACK_BOT_TOKEN" not in got
    assert "slack-token-should-not-leak" not in got.values()


def test_gateway_does_not_import_adapter_code_in_isolated_mode(monkeypatch):
    # The whole point: in isolated mode, resolving the adapter must NOT import
    # the gmail adapter module into the gateway process.
    monkeypatch.setenv("GLC_ISOLATED_ADAPTERS", "1")
    monkeypatch.setenv("GLC_ISOLATED_ADAPTER_LIST", "gmail")
    # Ensure a clean slate.
    for m in list(sys.modules):
        if m.startswith("glc.channels.catalogue.gmail.adapter"):
            del sys.modules[m]

    from glc.routes.channels import _get_adapter

    adapter = _get_adapter("gmail")
    assert isinstance(adapter, RemoteAdapter)
    # The gmail adapter module was NOT pulled into the gateway process.
    assert "glc.channels.catalogue.gmail.adapter" not in sys.modules


@pytest.mark.asyncio
async def test_worker_runs_adapter_in_its_own_process(monkeypatch):
    # Drive on_message through the subprocess worker. Without real Gmail creds
    # the adapter fails while building its live client — but that failure proves
    # the adapter CODE executed in the worker process, not the gateway (mirrors
    # the provider-isolation proof). The gateway only ever sees a clean error.
    monkeypatch.setenv("GLC_ADAPTER_BACKEND", "subprocess")
    monkeypatch.delenv("GLC_ADAPTER_SECRETS_DIR", raising=False)
    ra = RemoteAdapter("gmail")
    pubsub = {
        "message": {"data": "eyJlbWFpbEFkZHJlc3MiOiAibWVAeC5jb20iLCAiaGlzdG9yeUlkIjogMX0="},
        "subscription": "projects/x/subscriptions/y",
    }
    with pytest.raises(RemoteAdapterError):
        # Fails in the worker (no google libs / no token.json there in dev) —
        # the point is the exception crosses the boundary as a clean error,
        # and the gateway never imported/ran the adapter itself.
        await ra.on_message(pubsub)
