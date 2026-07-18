"""Leak 4 (invariant 2/4): when the install token is delivered via a Secret
(GLC_INSTALL_TOKEN), the gateway uses it and never writes it to the shared
config Volume where a co-located adapter could read it."""

from __future__ import annotations

from glc.config import get_or_create_install_token, install_token_path


def test_env_token_is_used_and_not_written(monkeypatch):
    monkeypatch.setenv("GLC_INSTALL_TOKEN", "secret-delivered-token")
    tok = get_or_create_install_token()
    assert tok == "secret-delivered-token"
    # The token is NOT persisted to disk in Secret mode.
    assert not install_token_path().exists()


def test_falls_back_to_disk_without_env(monkeypatch):
    monkeypatch.delenv("GLC_INSTALL_TOKEN", raising=False)
    tok = get_or_create_install_token()
    assert tok
    assert install_token_path().exists()
