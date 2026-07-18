"""Finding A1/A2: the public data plane must require the gateway API key.

These tests turn the auth gate on (the behaviour suite runs with it off) and
assert that data-plane routes reject anonymous callers, accept the configured
key, and that docs/openapi stay closed unless explicitly enabled.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def auth_client(monkeypatch, tmp_path):
    monkeypatch.setenv("GLC_REQUIRE_AUTH", "1")
    monkeypatch.setenv("GLC_GATEWAY_API_KEY", "s3cret-key")
    monkeypatch.setenv("GLC_ENABLE_DOCS", "0")
    import glc.main as m

    importlib.reload(m)  # rebuild the app with docs disabled + auth required
    with TestClient(m.app) as c:
        yield c
    # Restore a docs-enabled app object for any later tests in the process.
    monkeypatch.setenv("GLC_ENABLE_DOCS", "1")
    importlib.reload(m)


def test_chat_without_key_is_401(auth_client):
    r = auth_client.post("/v1/chat", json={"prompt": "hi", "provider": "gemini"})
    assert r.status_code == 401


def test_chat_with_wrong_key_is_403(auth_client):
    r = auth_client.post(
        "/v1/chat",
        json={"prompt": "hi", "provider": "gemini"},
        headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 403


def test_status_requires_key(auth_client):
    assert auth_client.get("/v1/status").status_code == 401


def test_providers_requires_key(auth_client):
    assert auth_client.get("/v1/providers").status_code == 401


def test_docs_and_openapi_disabled(auth_client):
    assert auth_client.get("/openapi.json").status_code == 404
    assert auth_client.get("/docs").status_code == 404


def test_healthz_stays_open(auth_client):
    # Liveness must not require the key so orchestrators can probe it.
    assert auth_client.get("/healthz").status_code == 200


def test_valid_key_passes_gate(auth_client):
    # With a valid key the request clears auth and reaches the provider layer;
    # with mock keys that surfaces as a provider/availability error, not 401/403.
    r = auth_client.post(
        "/v1/chat",
        json={"prompt": "hi", "provider": "gemini"},
        headers={"Authorization": "Bearer s3cret-key"},
    )
    assert r.status_code not in (401, 403)


def test_fail_closed_when_key_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("GLC_REQUIRE_AUTH", "1")
    monkeypatch.delenv("GLC_GATEWAY_API_KEY", raising=False)
    monkeypatch.setenv("GLC_ENABLE_DOCS", "1")
    import glc.main as m

    importlib.reload(m)
    with TestClient(m.app) as c:
        r = c.post("/v1/chat", json={"prompt": "hi"}, headers={"Authorization": "Bearer anything"})
        assert r.status_code == 503
    importlib.reload(m)
