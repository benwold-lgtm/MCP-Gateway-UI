# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7, slice 7 — the provider-plane raise/poll/release routes.

Replaces the act-on-tenant/elevated-grant routes removed at slice 6. The properties that
matter here: raising and polling relay with the BFF's *own* service credential (the operator
has no gateway credential of their own yet — that is the entire reason to raise a request),
`provider_subject` is the session's own identity and never client-supplied, and an approved
credential lands on the session so `security.upstream_bearer` can find it on a later call.
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

PROVIDER_ISS = "https://provider-idp.example.com"


class _Gateway:
    """Records every call the BFF makes to the gateway, and answers canned responses keyed
    by (method, path) — a fake `GatewayClient`, not a real one."""

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
def provider_console(monkeypatch):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    app = create_app()
    gw = _Gateway()
    # Monkeypatched onto the real GatewayClient instance, not swapped wholesale, so
    # `.aclose()` (called by the app's own lifespan shutdown) still exists.
    app.state.gateway.get = gw.get
    app.state.gateway.request = gw.request
    with TestClient(app) as c:
        yield c, app, gw


def _seed_provider_session(client, app, *, sub: str = "op-14", scopes=("provider:admin",)) -> None:
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    store = app.state.sessions
    live = store._data
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, {"kind": "oidc", "plane": "provider", "sub": sub, "provider_scopes": list(scopes)})


def test_raising_relays_with_the_bffs_own_credential_and_the_sessions_subject(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app, sub="op-14")
    gw.when("POST", "/support-requests", httpx.Response(201, json={"request_id": "r1", "expires_at": 123.0}))

    resp = client.post(
        "/provider/support-requests", json={"requested_scopes": ["devices:read"], "justification": "INC-9001"}
    )

    assert resp.status_code == 200
    assert resp.json() == {"request_id": "r1", "expires_at": 123.0}
    [call] = gw.calls
    assert call["method"] == "POST" and call["path"] == "/support-requests"
    assert call["bearer"] is None  # the BFF's own configured token, not the operator's
    assert call["json"]["provider_subject"] == "op-14"
    assert call["json"]["requested_scopes"] == ["devices:read"]


def test_the_client_cannot_assert_a_different_provider_subject(provider_console):
    """`provider_subject` names the operator for the gateway's own attribution — it must
    come from the session, never from anything the browser sends."""
    client, app, gw = provider_console
    _seed_provider_session(client, app, sub="op-14")
    gw.when("POST", "/support-requests", httpx.Response(201, json={"request_id": "r1"}))

    client.post(
        "/provider/support-requests",
        json={"requested_scopes": ["devices:read"], "justification": "x", "provider_subject": "someone-else"},
    )

    assert gw.calls[0]["json"]["provider_subject"] == "op-14"


def test_an_upstream_refusal_is_passed_through(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app)
    gw.when("POST", "/support-requests", httpx.Response(400, json={"detail": "'justification' is required"}))

    resp = client.post("/provider/support-requests", json={"requested_scopes": ["devices:read"], "justification": ""})

    assert resp.status_code == 400
    assert "justification" in resp.json()["detail"]


def test_polling_a_pending_request_does_not_touch_the_session(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app)
    gw.when("GET", "/support-requests/r1?provider_subject=op-14", httpx.Response(200, json={"status": "pending"}))

    resp = client.get("/provider/support-requests/r1")

    assert resp.json() == {"status": "pending"}
    assert client.get("/provider/support-grant").json() == {"held": False}


def test_polling_an_approved_request_stores_the_credential_on_the_session(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app)
    gw.when(
        "GET",
        "/support-requests/r1?provider_subject=op-14",
        httpx.Response(200, json={"status": "approved", "grant_id": "g1", "credential": "sgr_abc123"}),
    )

    resp = client.get("/provider/support-requests/r1")

    assert resp.json() == {"status": "approved", "grant_id": "g1", "credential": "sgr_abc123"}
    held = client.get("/provider/support-grant").json()
    assert held == {"held": True, "grant_id": "g1"}


def test_the_held_grant_view_never_exposes_the_credential_itself(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app)
    gw.when(
        "GET",
        "/support-requests/r1?provider_subject=op-14",
        httpx.Response(200, json={"status": "approved", "grant_id": "g1", "credential": "sgr_secret"}),
    )
    client.get("/provider/support-requests/r1")

    body = client.get("/provider/support-grant").json()

    assert "credential" not in body
    assert "sgr_secret" not in str(body)


def test_releasing_a_held_grant_relays_the_revoke_and_clears_the_session(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app)
    gw.when(
        "GET",
        "/support-requests/r1?provider_subject=op-14",
        httpx.Response(200, json={"status": "approved", "grant_id": "g1", "credential": "sgr_abc"}),
    )
    client.get("/provider/support-requests/r1")
    gw.when("DELETE", "/support-grants/g1", httpx.Response(204))

    resp = client.delete("/provider/support-grant")

    assert resp.json() == {"released": "g1"}
    assert client.get("/provider/support-grant").json() == {"held": False}
    assert any(c["method"] == "DELETE" and c["path"] == "/support-grants/g1" for c in gw.calls)


def test_releasing_with_nothing_held_is_a_harmless_no_op(provider_console):
    client, app, gw = provider_console
    _seed_provider_session(client, app)

    resp = client.delete("/provider/support-grant")

    assert resp.json() == {"released": None}
    assert not any(c["path"].startswith("/support-grants/") for c in gw.calls)


def test_a_tenant_session_cannot_reach_these_routes(provider_console):
    """The mirror-image wall: `require_provider_scope` refuses a tenant-plane session."""
    client, app, gw = provider_console
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200

    resp = client.post("/provider/support-requests", json={"requested_scopes": [], "justification": "x"})

    assert resp.status_code == 403
