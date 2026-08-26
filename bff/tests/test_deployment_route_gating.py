# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0021 (scoped) slice 5 — a tenant deployment and a provider deployment mount a
different route surface (`main.create_app`). This is a leaner-API-surface measure, not a
security boundary in its own right: every route gated `provider.router`/`catalog.router`
already requires a provider-plane session (which a tenant deployment's own sessions can
never be) and every route in `support.router` already requires `require_role`, which a
provider deployment's own sessions can only ever satisfy while holding a grant for a
different tenant. What this pins is that the *wrong* routes are not even mounted, not that
they would otherwise be reachable — the 404 here is a routing fact, never itself the
security control.

`api.router` (the tenant data plane) is the one router common to both deployments — pinned
here too, since it is the one property this slice must NOT accidentally narrow: a provider
session's whole path to a held grant's tenant (`relay.py`) runs through it.
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


@pytest.fixture
def tenant_app(monkeypatch):
    monkeypatch.delenv("PROVIDER_OIDC_ENABLED", raising=False)
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def provider_app(monkeypatch):
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    with TestClient(create_app()) as c:
        yield c


def test_a_tenant_deployment_does_not_mount_provider_routes(tenant_app):
    assert tenant_app.post("/provider/support-requests", json={}).status_code == 404
    assert tenant_app.get("/provider/tenants").status_code == 404
    assert tenant_app.get("/provider/catalog/device-types").status_code == 404


def test_a_tenant_deployment_still_mounts_the_tenant_inbox(tenant_app):
    """Unauthenticated, so 401 — the point here is "routed at all", not "authorized"."""
    assert tenant_app.get("/api/support/requests").status_code == 401


def test_a_tenant_deployment_still_mounts_the_tenant_data_plane(tenant_app):
    assert tenant_app.get("/api/devices").status_code == 401


def test_a_provider_deployment_does_not_mount_the_tenant_inbox(provider_app):
    assert provider_app.get("/api/support/requests").status_code == 404
    assert provider_app.get("/api/notifications").status_code == 404


def test_a_provider_deployment_still_mounts_provider_routes(provider_app):
    assert provider_app.get("/provider/tenants").status_code == 401
    assert provider_app.get("/provider/catalog/device-types").status_code == 401


def test_a_provider_deployment_still_mounts_the_tenant_data_plane(provider_app):
    """The one router common to both — a provider session's held-grant relay (`relay.py`,
    ADR-0021 scoped slices 2/3) depends on `/api/*` being reachable on this same process."""
    assert provider_app.get("/api/devices").status_code == 401
