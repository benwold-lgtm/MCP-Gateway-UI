# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §1/§2, slice 3 — the provider-plane curation/assignment relay.

This router holds no storage of its own; every route either relays to the catalog service
(`app.state.catalog`, faked here the same way `test_elevated_routes.py` fakes
`app.state.gateway`) or refuses before reaching it. Three properties carry this slice:

1. **Provider-plane only** — a tenant session, an unauthenticated request, and a provider
   session lacking `provider:admin` are each refused, mirroring `provider.py`'s existing
   act-on-tenant routes.
2. **`assigned_by` is never taken from the browser** — the session's own subject is what
   this BFF can vouch for; a client-supplied value would be an unverified audit attribution.
3. **Catalog unavailability is a named condition (503), not a 500 and not empty data**
   (ADR-0020 §7) — and reads are unaudited, mutations are, matching `api.py`'s own
   read/write audit split.
"""

from __future__ import annotations

import os
from typing import Optional

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.catalog_client import CatalogUnavailable  # noqa: E402
from app.main import create_app  # noqa: E402
from app.security import PLANE_PROVIDER, PLANE_TENANT, SCOPE_PROVIDER_ADMIN, SCOPE_PROVIDER_MONITOR  # noqa: E402

PROVIDER_ISS = "https://provider-idp.example.com"


def _provider_session(**over) -> dict:
    sess = {
        "kind": "oidc",
        "plane": PLANE_PROVIDER,
        "sub": "u-provider-1",
        "provider_scopes": [SCOPE_PROVIDER_ADMIN],
    }
    sess.update(over)
    return sess


def _tenant_session(**over) -> dict:
    sess = {"kind": "oidc", "plane": PLANE_TENANT, "sub": "u-tenant-1", "role": "admin"}
    sess.update(over)
    return sess


@pytest.fixture
def console(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("CATALOG_SERVICE_URL", "http://catalog.internal")
    monkeypatch.setenv("CATALOG_API_TOKEN", "catalog-token")
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _seed_session(client, app, data: dict) -> None:
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    store = app.state.sessions
    live = getattr(store, "_data", None)
    assert live is not None, "seeding assumes the in-memory store"
    assert len(live) == 1
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, dict(data))


def _audited(app, tenant: str, action: str) -> list[dict]:
    rows = app.state.audit.read(tenant=tenant, limit=200)
    return [r["content"] for r in reversed(rows) if r["content"] and r["content"]["action"] == action]


class _FakeCatalog:
    """Records every relayed call and answers canned responses — the same shape
    `test_elevated_routes.py`'s `_Upstream` uses for `app.state.gateway`."""

    def __init__(self, *, status: int = 200, payload=None):
        self.status = status
        self.payload = payload if payload is not None else {"ok": True}
        self.calls: list[dict] = []
        self._raise: Optional[Exception] = None

    def fail(self, exc: Exception) -> None:
        self._raise = exc

    async def request(self, method, path, *, json=None):
        self.calls.append({"method": method, "path": path, "json": json})
        if self._raise is not None:
            raise self._raise
        return httpx.Response(self.status, json=self.payload)


def _attach(app, fake: _FakeCatalog) -> _FakeCatalog:
    app.state.catalog.request = fake.request
    return fake


# --- plane isolation ------------------------------------------------------------------


def test_unauthenticated_is_refused(console):
    client, app = console
    resp = client.get("/provider/catalog/device-types")
    assert resp.status_code == 401


def test_a_tenant_session_cannot_reach_catalog_routes(console):
    client, app = console
    _seed_session(client, app, _tenant_session())
    resp = client.get("/provider/catalog/device-types")
    assert resp.status_code == 403


def test_a_provider_session_without_admin_scope_is_refused(console):
    client, app = console
    _seed_session(client, app, _provider_session(provider_scopes=[SCOPE_PROVIDER_MONITOR]))
    resp = client.get("/provider/catalog/device-types")
    assert resp.status_code == 403


# --- curation relay --------------------------------------------------------------------


def test_create_device_type_relays_the_body_and_audits(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    fake = _attach(app, _FakeCatalog(status=201, payload={"id": "t1", "slug": "acme-x1"}))

    resp = client.post("/provider/catalog/device-types", json={"slug": "acme-x1", "name": "Acme X1"})

    assert resp.status_code == 201
    assert resp.json()["slug"] == "acme-x1"
    assert fake.calls == [{"method": "POST", "path": "/device-types", "json": {"slug": "acme-x1", "name": "Acme X1"}}]
    records = _audited(app, "default", "provider.catalog.device_type.create")
    assert len(records) == 1
    assert records[0]["outcome"] == "success"


def test_add_version_relays_to_the_right_path(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    fake = _attach(app, _FakeCatalog(status=201))

    resp = client.post("/provider/catalog/device-types/t1/versions", json={"changelog": "bumped a timeout"})

    assert resp.status_code == 201
    assert fake.calls[0]["path"] == "/device-types/t1/versions"


def test_list_device_types_is_a_read_and_is_not_audited(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    _attach(app, _FakeCatalog(payload={"device_types": []}))

    resp = client.get("/provider/catalog/device-types")

    assert resp.status_code == 200
    assert _audited(app, "default", "provider.catalog.device_type.create") == []


def test_get_device_type_relays_the_id(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    fake = _attach(app, _FakeCatalog(payload={"id": "t1"}))

    resp = client.get("/provider/catalog/device-types/t1")

    assert resp.status_code == 200
    assert fake.calls[0]["path"] == "/device-types/t1"


# --- assignment relay ------------------------------------------------------------------


def test_assign_overrides_assigned_by_with_the_sessions_own_subject(console):
    """The whole point: a browser cannot assert its own audit attribution."""
    client, app = console
    _seed_session(client, app, _provider_session(sub="u-provider-1"))
    fake = _attach(app, _FakeCatalog(status=201, payload={"id": "a1"}))

    resp = client.post(
        "/provider/catalog/device-types/t1/assign",
        json={"tenant_id": "mcp-t-abc", "assigned_by": "someone-else-entirely"},
    )

    assert resp.status_code == 201
    assert fake.calls[0]["json"] == {"tenant_id": "mcp-t-abc", "assigned_by": "u-provider-1"}
    records = _audited(app, "default", "provider.catalog.assign")
    assert len(records) == 1


def test_assign_requires_a_tenant_id_and_never_reaches_the_catalog_without_one(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    fake = _attach(app, _FakeCatalog())

    resp = client.post("/provider/catalog/device-types/t1/assign", json={})

    assert resp.status_code == 400
    assert fake.calls == []


def test_revoke_passes_through_204_with_no_body(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    _attach(app, _FakeCatalog(status=204, payload={}))

    resp = client.delete("/provider/catalog/device-types/t1/assign/mcp-t-abc")

    assert resp.status_code == 204
    records = _audited(app, "default", "provider.catalog.revoke")
    assert len(records) == 1


def test_revoke_404_passes_through_and_is_audited(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    _attach(app, _FakeCatalog(status=404, payload={"detail": "no active assignment"}))

    resp = client.delete("/provider/catalog/device-types/t1/assign/mcp-t-abc")

    assert resp.status_code == 404
    records = _audited(app, "default", "provider.catalog.revoke")
    # outcome_for(404) is "error", not "denied" — 401/403 are the only statuses that map
    # to "denied" (see audit.py's own docstring on why).
    assert records[0]["outcome"] == "error"


def test_tenant_assignments_is_a_read_and_is_not_audited(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    fake = _attach(app, _FakeCatalog(payload={"device_types": []}))

    resp = client.get("/provider/catalog/tenants/mcp-t-abc/assignments")

    assert resp.status_code == 200
    assert fake.calls[0]["path"] == "/tenants/mcp-t-abc/assignments"
    assert _audited(app, "default", "provider.catalog.assign") == []


# --- catalog unavailable -----------------------------------------------------------------


def test_catalog_unavailable_is_a_named_503_not_a_crash(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    fake = _attach(app, _FakeCatalog())
    fake.fail(CatalogUnavailable("connection refused"))

    resp = client.get("/provider/catalog/device-types")

    assert resp.status_code == 503
    assert "catalog service unavailable" in resp.json()["detail"]
