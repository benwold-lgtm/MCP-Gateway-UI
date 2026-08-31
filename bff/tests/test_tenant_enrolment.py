# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §10 — the tenant's own half of enrolment, in the tenant console.

The provider console redeems (`test_provider_enrolment.py`); this is the side that *issues* the
invitation and can end the relationship afterwards. Both halves are needed for §10's model to
be real: it chose revocation over expiry, which only works if the tenant can actually see who is
enrolled and act on it.

What is tested hardest here:

* the **invitation code never reaches a durable record on this side** — it is a one-time secret
  in flight, and a console that audited the response body would write it to disk in the one
  place §10 promised it would not exist;
* **revocation is reachable and attributable**, since it is the only control an enrolment has;
* every route is **admin-gated and tenant-plane**, like the support inbox it sits beside.
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

INVITATION_CODE = "inv_a-one-time-secret"


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
    assert client.post("/auth/login", json={"password": f"{role}-pw"}).status_code == 200


def _actions(app) -> list[str]:
    return [r["content"]["action"] for r in app.state.audit.read(tenant="default", limit=50) if r["content"]]


def _audit_text(app) -> str:
    return str(app.state.audit.read(tenant="default", limit=50))


# --- issuing an invitation ------------------------------------------------------------------


def test_creating_an_invitation_relays_the_label_and_returns_the_code(console):
    client, app, gw = console
    _login(client)
    gw.when(
        "POST",
        "/enrolment-invitations",
        httpx.Response(201, json={"code": INVITATION_CODE, "provider_label": "Acme MSP", "expires_at": 999.0}),
    )

    resp = client.post("/api/enrolment/invitations", json={"provider_label": "Acme MSP", "ttl_seconds": 3600})

    assert resp.status_code == 201
    assert resp.json()["code"] == INVITATION_CODE
    assert gw.calls[-1]["json"] == {"provider_label": "Acme MSP", "ttl_seconds": 3600}
    assert "tenant.enrolment_invitation.create" in _actions(app)


def test_the_invitation_code_is_never_written_to_the_audit_record(console):
    """§10: the plaintext is in the gateway's response and nowhere else. A console that audited
    the response body would put it on disk in the one place the record promised it would not
    exist — and unlike the response in flight, that copy persists."""
    client, app, gw = console
    _login(client)
    gw.when("POST", "/enrolment-invitations", httpx.Response(201, json={"code": INVITATION_CODE}))

    client.post("/api/enrolment/invitations", json={"provider_label": "Acme MSP"})

    assert INVITATION_CODE not in _audit_text(app)


def test_a_refusal_is_passed_through_rather_than_flattened(console):
    """The gateway refuses an invitation with no `provider_label` — one nobody can attribute is
    one nobody can safely hand over. The operator needs to see that reason, not a generic 502."""
    client, app, gw = console
    _login(client)
    gw.when("POST", "/enrolment-invitations", httpx.Response(400, json={"detail": "provider_label is required"}))

    resp = client.post("/api/enrolment/invitations", json={})

    assert resp.status_code == 400
    assert "provider_label" in resp.json()["detail"]


def test_listing_invitations_is_a_read_and_is_not_audited(console):
    client, app, gw = console
    _login(client)
    gw.when("GET", "/enrolment-invitations", httpx.Response(200, json={"invitations": [{"code_hash": "h1"}]}))

    resp = client.get("/api/enrolment/invitations")

    assert resp.json() == {"invitations": [{"code_hash": "h1"}]}
    assert "tenant.enrolment_invitation.create" not in _actions(app)


def test_revoking_an_invitation_relays_and_audits(console):
    client, app, gw = console
    _login(client)
    gw.when("DELETE", "/enrolment-invitations/h1", httpx.Response(204))

    resp = client.delete("/api/enrolment/invitations/h1")

    assert resp.status_code == 204
    assert "tenant.enrolment_invitation.revoke" in _actions(app)


# --- the live relationships -----------------------------------------------------------------


def test_listing_enrolments_carries_last_used_at(console):
    """The field this screen exists for. §10 chose revocation over expiry, so a dormant
    relationship is discoverable only by looking — a console that dropped `last_used_at` would
    leave that decision's one safeguard unexercised."""
    client, app, gw = console
    _login(client)
    gw.when(
        "GET",
        "/enrolments",
        httpx.Response(
            200,
            json={
                "enrolments": [
                    {"enrolment_id": "e-1", "provider_label": "Acme MSP", "last_used_at": None},
                    {"enrolment_id": "e-2", "provider_label": "Other MSP", "last_used_at": 1234.0},
                ]
            },
        ),
    )

    body = client.get("/api/enrolment/enrolments").json()

    assert [e["last_used_at"] for e in body["enrolments"]] == [None, 1234.0]


def test_the_enrolment_listing_never_carries_a_credential(console):
    """The gateway keeps the tenant's catalog credential behind its own route rather than as a
    field here, for the reason it states: a listing is a screen an admin leaves open. This
    asserts the console relays that listing rather than enriching it."""
    client, app, gw = console
    _login(client)
    gw.when("GET", "/enrolments", httpx.Response(200, json={"enrolments": [{"enrolment_id": "e-1"}]}))

    body = client.get("/api/enrolment/enrolments").json()

    assert body == {"enrolments": [{"enrolment_id": "e-1"}]}
    assert not any(c["path"].endswith("catalog-configuration") for c in gw.calls)


def test_revoking_an_enrolment_relays_and_audits(console):
    client, app, gw = console
    _login(client)
    gw.when("DELETE", "/enrolments/e-1", httpx.Response(204))

    resp = client.delete("/api/enrolment/enrolments/e-1")

    assert resp.status_code == 204
    assert "tenant.enrolment.revoke" in _actions(app)


def test_revoking_twice_is_not_an_error_the_console_invents(console):
    """The gateway is idempotent here on purpose (ADR-0017 §8): a tenant admin ending a supplier
    relationship is usually doing it because something is wrong right now, and a button that
    errors on the second click fails when it matters. The console must not re-add that error."""
    client, app, gw = console
    _login(client)
    gw.when("DELETE", "/enrolments/e-1", httpx.Response(204))

    assert client.delete("/api/enrolment/enrolments/e-1").status_code == 204
    assert client.delete("/api/enrolment/enrolments/e-1").status_code == 204


# --- authority ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/enrolment/invitations"),
        ("GET", "/api/enrolment/invitations"),
        ("DELETE", "/api/enrolment/invitations/h1"),
        ("GET", "/api/enrolment/enrolments"),
        ("DELETE", "/api/enrolment/enrolments/e-1"),
    ],
)
def test_every_route_needs_admin(console, method, path):
    """Fleet-governance authority, like backup/restore and the support inbox beside it — not
    routine read access. Even the listings: who your provider is and when they last reached in
    is not something a viewer session should be able to enumerate."""
    client, app, gw = console
    _login(client, role="viewer")
    assert client.request(method, path, json={}).status_code == 403


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/enrolment/invitations"),
        ("GET", "/api/enrolment/enrolments"),
    ],
)
def test_unauthenticated_is_refused(console, method, path):
    client, app, gw = console
    assert client.request(method, path, json={}).status_code == 401


def test_the_provider_console_does_not_serve_the_tenants_half(monkeypatch, tmp_path):
    """Plane isolation by construction, the arrangement `main.py` already uses: `support.router`
    is mounted only on a tenant console and `routers/enrolment.py` only on a provider one. The
    two halves of the handshake never coexist in one process."""
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", "https://provider.idp.invalid")
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))

    with TestClient(create_app()) as c:
        assert c.get("/api/enrolment/enrolments").status_code == 404


# --- what the provider needs from us --------------------------------------------------------
#
# §10's handshake needs three values: the invitation code, this tenant's id, and the gateway
# address a provider can actually reach. The console produced the first and showed neither of
# the others, so issuing an invitation left an admin to read a tenant id out of a ConfigMap.


def test_the_console_can_tell_an_admin_what_to_hand_over(console, monkeypatch):
    monkeypatch.setenv("TENANT_ID", "t-abc")
    monkeypatch.setenv("PUBLIC_GATEWAY_URL", "https://gw.tenant.example")
    app = create_app()
    with TestClient(app) as client:
        _login(client)
        resp = client.get("/api/enrolment/this-tenant")

    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": "t-abc", "public_gateway_url": "https://gw.tenant.example"}


def test_an_unconfigured_public_url_is_reported_empty_never_guessed(console, monkeypatch):
    """The BFF knows an in-cluster GATEWAY_URL, and substituting it here would be worse than
    saying nothing: it looks like an answer and fails at redemption, in the *provider's*
    console, with an error naming neither this field nor this tenant."""
    monkeypatch.setenv("TENANT_ID", "t-abc")
    monkeypatch.delenv("PUBLIC_GATEWAY_URL", raising=False)
    monkeypatch.setenv("GATEWAY_URL", "http://device-mcp-gateway.internal.svc.cluster.local:8000")
    app = create_app()
    with TestClient(app) as client:
        _login(client)
        body = client.get("/api/enrolment/this-tenant").json()

    assert body["public_gateway_url"] == ""
    assert "cluster.local" not in str(body), "the in-cluster address leaked into the handover details"


def test_handover_details_are_admin_only_like_the_rest_of_enrolment(console):
    client, _app, _gw = console
    _login(client, role="viewer")
    assert client.get("/api/enrolment/this-tenant").status_code == 403
