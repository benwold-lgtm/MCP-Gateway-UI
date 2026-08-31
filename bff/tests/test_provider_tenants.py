# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0021 (scoped) slice 1 — GET /provider/tenants, the provider console's own directory
of known tenants. Pure navigation: which tenants exist and their display names, never their
gateway URLs (an internal topology detail the browser has no need for) and never a statement
about whether a support request against any of them would be approved (ADR-0017's tenant-side
approval is the only authority that decides that).
"""

from __future__ import annotations

import os

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402

PROVIDER_ISS = "https://provider-idp.example.com"

REGISTRY = (
    '[{"tenant_id": "t-2", "display_name": "Zeta Corp", "gateway_url": "http://t2:8000"},'
    ' {"tenant_id": "t-1", "display_name": "Acme Inc", "gateway_url": "http://t1:8000"}]'
)


@pytest.fixture
def provider_console(monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv(
        "PROVIDER_GROUP_SCOPES",
        '{"provider-support": "provider:admin", "provider-noc": "provider:monitor"}',
    )
    monkeypatch.setenv("PROVIDER_TENANT_REGISTRY", REGISTRY)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _seed_provider_session(client, app, *, sub: str = "op-14", scopes) -> None:
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    store = app.state.sessions
    live = store._data
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, {"kind": "oidc", "plane": "provider", "sub": sub, "provider_scopes": list(scopes)})


def test_unauthenticated_is_refused(provider_console):
    c, _ = provider_console
    resp = c.get("/provider/tenants")
    assert resp.status_code == 401


def test_a_tenant_session_cannot_reach_it(provider_console):
    c, app = provider_console
    resp = c.post("/auth/login", json={"password": "viewer-pw"})
    assert resp.status_code == 200
    resp = c.get("/provider/tenants")
    assert resp.status_code == 403


def test_monitor_scope_alone_is_admitted(provider_console):
    c, app = provider_console
    _seed_provider_session(c, app, scopes=["provider:monitor"])
    resp = c.get("/provider/tenants")
    assert resp.status_code == 200


def test_admin_scope_alone_is_admitted(provider_console):
    c, app = provider_console
    _seed_provider_session(c, app, scopes=["provider:admin"])
    resp = c.get("/provider/tenants")
    assert resp.status_code == 200


def test_lists_tenants_sorted_by_display_name_without_gateway_url(provider_console):
    c, app = provider_console
    _seed_provider_session(c, app, scopes=["provider:monitor"])
    resp = c.get("/provider/tenants")
    assert resp.status_code == 200
    assert resp.json() == {
        "tenants": [
            {"tenant_id": "t-1", "display_name": "Acme Inc"},
            {"tenant_id": "t-2", "display_name": "Zeta Corp"},
        ],
        # ADR-0024 §11: config is the floor and the catalog is the live source. With no catalog
        # configured this console is not degraded, it is a supported arrangement — so `stale` is
        # False. A permanent warning on every deployment that has not adopted enrolment would be
        # the opposite of what §11 promised that audience.
        "stale": False,
    }


def test_an_empty_registry_lists_no_tenants(monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.delenv("PROVIDER_TENANT_REGISTRY", raising=False)
    app = create_app()
    with TestClient(app) as c:
        _seed_provider_session(c, app, scopes=["provider:admin"])
        resp = c.get("/provider/tenants")
    assert resp.status_code == 200
    assert resp.json() == {"tenants": [], "stale": False}


def test_a_malformed_registry_refuses_to_boot(monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_TENANT_REGISTRY", "{not json")
    with pytest.raises(RuntimeError, match="not valid JSON"):
        create_app()
