"""Part 2 bug: webhook subscription verification must fail closed.

GET /v1/channels/{name}/webhook compares hub.verify_token to the per-channel
{NAME}_VERIFY_TOKEN env var. When that var is unset the expected value is ""
and hmac.compare_digest("", "") is True, so an empty presented token passes —
a fail-open bypass. The fix rejects unless a non-empty token is configured.
Breaks invariant 2 (an authenticity check passes when it must not).
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_unconfigured_channel_rejects_empty_token(app_client: TestClient, monkeypatch):
    monkeypatch.delenv("WEBUI_VERIFY_TOKEN", raising=False)
    r = app_client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "", "hub.challenge": "PWNED"},
    )
    assert r.status_code == 403


def test_unconfigured_channel_rejects_any_token(app_client: TestClient, monkeypatch):
    monkeypatch.delenv("WEBUI_VERIFY_TOKEN", raising=False)
    r = app_client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "guess", "hub.challenge": "PWNED"},
    )
    assert r.status_code == 403


def test_configured_channel_accepts_correct_token(app_client: TestClient, monkeypatch):
    monkeypatch.setenv("WEBUI_VERIFY_TOKEN", "s3cret")
    r = app_client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "s3cret", "hub.challenge": "OK123"},
    )
    assert r.status_code == 200
    assert r.text == "OK123"


def test_configured_channel_rejects_wrong_token(app_client: TestClient, monkeypatch):
    monkeypatch.setenv("WEBUI_VERIFY_TOKEN", "s3cret")
    r = app_client.get(
        "/v1/channels/webui/webhook",
        params={"hub.mode": "subscribe", "hub.verify_token": "wrong", "hub.challenge": "OK123"},
    )
    assert r.status_code == 403
