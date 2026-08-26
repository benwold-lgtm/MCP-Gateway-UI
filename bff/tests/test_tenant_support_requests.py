# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7, slice 7 — the tenant-plane support-management + notification routes.

The other half of `test_provider_support_requests.py`: a tenant admin's own inbox, standing
consent, and the durable notification list. Unlike the provider-plane routes, these relay
with the *caller's own* credential (`upstream_bearer`) — a password session proxies with the
BFF's admin token, an OIDC tenant session with its own — so the decision is attributable to
the human who made it in the gateway's own audit chain, not collapsed into a service identity.
"""

from __future__ import annotations

import os

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402


class _Gateway:
    def __init__(self):
        self.calls: list[dict] = []
        self.responses: dict[tuple[str, str], httpx.Response] = {}

    def when(self, method: str, path: str, response: httpx.Response) -> None:
        self.responses[(method, path)] = response

    async def request(self, method, path, *, json=None, bearer=None, headers=None):
        self.calls.append({"method": method, "path": path, "json": json, "bearer": bearer})
        return self.responses.get((method, path), httpx.Response(200, json={}))

    async def get(self, path, *, bearer=None):
        return await self.request("GET", path, bearer=bearer)


@pytest.fixture
def console(tmp_path, monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    app = create_app()
    gw = _Gateway()
    app.state.gateway.get = gw.get
    app.state.gateway.request = gw.request
    with TestClient(app) as c:
        yield c, app, gw


def _login(client, role="admin"):
    resp = client.post("/auth/login", json={"password": f"{role}-pw"})
    assert resp.status_code == 200


def test_admin_lists_pending_requests(console):
    client, app, gw = console
    _login(client)
    gw.when("GET", "/support-requests", httpx.Response(200, json={"requests": [{"request_id": "r1"}]}))

    resp = client.get("/api/support/requests")

    assert resp.status_code == 200
    assert resp.json() == {"requests": [{"request_id": "r1"}]}


def test_a_viewer_cannot_reach_the_inbox(console):
    client, app, gw = console
    _login(client, role="viewer")

    resp = client.get("/api/support/requests")

    assert resp.status_code == 403


def test_approve_relays_and_audits(console):
    client, app, gw = console
    _login(client)
    gw.when("POST", "/support-requests/r1/approve", httpx.Response(200, json={"grant_id": "g1", "expires_at": 999.0}))

    resp = client.post("/api/support/requests/r1/approve")

    assert resp.status_code == 200
    assert resp.json() == {"grant_id": "g1", "expires_at": 999.0}
    rows = app.state.audit.read(tenant="default", limit=50)
    actions = [r["content"]["action"] for r in rows if r["content"]]
    assert "tenant.support_request.approve" in actions


def test_reject_relays_and_audits(console):
    client, app, gw = console
    _login(client)
    gw.when("POST", "/support-requests/r1/reject", httpx.Response(204))

    resp = client.post("/api/support/requests/r1/reject")

    assert resp.status_code == 204
    rows = app.state.audit.read(tenant="default", limit=50)
    actions = [r["content"]["action"] for r in rows if r["content"]]
    assert "tenant.support_request.reject" in actions


def test_list_active_grants(console):
    client, app, gw = console
    _login(client)
    gw.when("GET", "/support-grants", httpx.Response(200, json={"grants": [{"id": "g1"}]}))

    resp = client.get("/api/support/grants")

    assert resp.json() == {"grants": [{"id": "g1"}]}


def test_revoke_a_grant_relays_and_audits(console):
    client, app, gw = console
    _login(client)
    gw.when("DELETE", "/support-grants/g1", httpx.Response(204))

    resp = client.delete("/api/support/grants/g1")

    assert resp.status_code == 204
    rows = app.state.audit.read(tenant="default", limit=50)
    actions = [r["content"]["action"] for r in rows if r["content"]]
    assert "tenant.support_grant.revoke" in actions


def test_standing_consent_round_trips(console):
    client, app, gw = console
    _login(client)
    gw.when(
        "POST",
        "/support-requests/standing-consent",
        httpx.Response(201, json={"scopes": ["devices:read"], "enabled_by": "key:admin", "expires_at": 1.0}),
    )
    gw.when(
        "GET",
        "/support-requests/standing-consent",
        httpx.Response(200, json={"enabled": True, "scopes": ["devices:read"]}),
    )

    enable = client.post("/api/support/standing-consent", json={"scopes": ["devices:read"]})
    read = client.get("/api/support/standing-consent")

    assert enable.status_code == 201
    assert read.json()["enabled"] is True
    rows = app.state.audit.read(tenant="default", limit=50)
    actions = [r["content"]["action"] for r in rows if r["content"]]
    assert "tenant.support_standing_consent.enable" in actions


def test_disabling_standing_consent_audits(console):
    client, app, gw = console
    _login(client)
    gw.when("DELETE", "/support-requests/standing-consent", httpx.Response(204))

    resp = client.delete("/api/support/standing-consent")

    assert resp.status_code == 204
    rows = app.state.audit.read(tenant="default", limit=50)
    actions = [r["content"]["action"] for r in rows if r["content"]]
    assert "tenant.support_standing_consent.disable" in actions


def test_lists_notifications_unaudited(console):
    client, app, gw = console
    _login(client)
    gw.when("GET", "/notifications", httpx.Response(200, json={"notifications": [{"kind": "break_glass.activated"}]}))

    resp = client.get("/api/notifications")

    assert resp.status_code == 200
    assert resp.json()["notifications"][0]["kind"] == "break_glass.activated"
    # A read, deliberately unaudited — same convention as every other list route.
    rows = app.state.audit.read(tenant="default", limit=50)
    actions = [r["content"]["action"] for r in rows if r["content"]]
    assert "notifications.list" not in actions


def test_a_provider_plane_session_cannot_reach_the_tenant_inbox(console, monkeypatch):
    """The converse wall: a provider session has no admin role to check against, so
    `require_role` refuses it outright (ADR-0017 slice 6/7)."""
    client, app, gw = console
    _login(client)
    store = app.state.sessions
    sid = next(iter(store._data))
    expires, _ = store._data[sid]
    store._data[sid] = (expires, {"kind": "oidc", "plane": "provider", "sub": "op-1", "provider_scopes": []})

    resp = client.get("/api/support/requests")

    assert resp.status_code == 403
