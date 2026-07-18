"""Shared fixtures.

Each test session gets a fresh isolated config/db dir so user state at
~/.glc/ is never touched. Per-test, the audit / pairing / gateway DBs
are rolled fresh.
"""

from __future__ import annotations

import os

import pytest

# A2: the OpenAPI schema and Swagger UI are disabled by default on public
# deployments. The route-registration tests introspect /openapi.json, so the
# suite opts docs back in. Set before glc.main is imported (module-level env
# is read at app-construction time).
os.environ.setdefault("GLC_ENABLE_DOCS", "1")


@pytest.fixture(autouse=True)
def _isolated_glc_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("GLC_PAIRING_DB", str(tmp_path / "pairings.sqlite"))
    monkeypatch.setenv("GLC_GATEWAY_DB", str(tmp_path / "gateway.sqlite"))
    # Data-plane auth (finding A1) defaults off for the behaviour suite, which
    # exercises v9 chat/embed semantics rather than the auth gate. The gate has
    # its own dedicated test (test_data_plane_auth.py) that turns it on.
    monkeypatch.setenv("GLC_REQUIRE_AUTH", "0")
    # Tests act as the installer/bootstrap: allow force_pair_owner (leak 3
    # guard defaults to denying it inside the serving gateway).
    monkeypatch.setenv("GLC_ALLOW_FORCE_PAIR", "1")

    # Reset singletons that cache config-dir at first access.
    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    import glc.policy.engine as _e

    _e._engine = None
    import glc.audit.store as _a

    _a._singleton = None
    import glc.security.budget as _b

    _b.reset_budget_for_tests()
    yield


@pytest.fixture
def app_client():
    """TestClient pointed at a freshly-booted glc.main:app."""
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as c:
        yield c


@pytest.fixture
def install_token(app_client):
    """Returns the per-installation token created during boot."""
    from glc.config import install_token_path

    return install_token_path().read_text().strip()
