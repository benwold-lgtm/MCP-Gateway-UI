# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §10 — the provider console redeems a tenant's invitation.

Three steps that were nine manual ones: mint the tenant's catalog credential, redeem the
invitation against the tenant's gateway, and verify the gateway reports the tenant we minted
for. What is tested hardest here is not the happy path but the two ways it can go wrong without
anyone noticing:

* a **credential orphaned** by a redemption that failed after minting — a live credential for a
  tenant that was never enrolled, which nothing else in the estate would ever attribute;
* a **tenant mismatch**, where an operator's typo mints for tenant A and installs in tenant B.
  ADR-0020 §7b catches that later, at the tenant's first catalog call, as a page. This catches
  it before the credential is ever installed.
"""

from __future__ import annotations

import os

# Set before importing the app, exactly as `test_provider_catalog.py` does: the password
# login used to seed a session reads these at import time.
os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402
from app.security import PLANE_PROVIDER, SCOPE_PROVIDER_ADMIN  # noqa: E402

TENANT = "t-aaaa"
GATEWAY_URL = "https://tenant-a.gateway.example"
CATALOG_URL = "http://catalog.internal"
CREDENTIAL_ID = "11111111-1111-1111-1111-111111111111"


def _provider_session(**over) -> dict:
    sess = {"kind": "oidc", "plane": PLANE_PROVIDER, "sub": "u-provider-1", "provider_scopes": [SCOPE_PROVIDER_ADMIN]}
    sess.update(over)
    return sess


@pytest.fixture
def console(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", "https://provider.idp.invalid")
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("CATALOG_SERVICE_URL", CATALOG_URL)
    monkeypatch.setenv("CATALOG_API_TOKEN", "catalog-token")
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _seed_session(client, app, data: dict) -> None:
    assert client.post("/auth/login", json={"password": "admin-pw"}).status_code == 200
    live = app.state.sessions._data
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, dict(data))


class _FakeCatalog:
    """Answers the two catalog calls this flow makes and records both, so a test can assert an
    orphaned credential was actually withdrawn rather than merely intended to be."""

    def __init__(self, *, issue_status: int = 201) -> None:
        self.calls: list[tuple[str, str]] = []
        self._issue_status = issue_status

    async def request(self, method: str, path: str, *, json=None):
        self.calls.append((method, path))
        if method == "POST":
            return httpx.Response(
                self._issue_status,
                json={"id": CREDENTIAL_ID, "tenant_id": TENANT, "label": "enrolment", "credential": "cat_secret"},
            )
        return httpx.Response(204)

    async def aclose(self) -> None:
        """The app's shutdown closes whatever is on `state.catalog`; a double that omitted this
        turned every test into a teardown error while still reporting the assertions passed."""

    @property
    def revoked(self) -> bool:
        return ("DELETE", f"/tenants/{TENANT}/credentials/{CREDENTIAL_ID}") in self.calls


def _gateway_responder(app, handler):
    """Point the redeem step's outbound httpx client at a mock transport."""
    import app.routers.enrolment as mod

    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw.pop("timeout", None)
        return real(transport=httpx.MockTransport(handler), **kw)

    mod.httpx.AsyncClient = factory  # type: ignore[assignment]
    return lambda: setattr(mod.httpx, "AsyncClient", real)


def _redeem(client, **over):
    body = {"code": "inv_abc", "gateway_url": GATEWAY_URL, "tenant_id": TENANT}
    body.update(over)
    return client.post("/provider/enrolment/redeem", json=body)


def _ok_gateway(tenant_id: str = TENANT):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json={
                "enrolment_id": "e-1",
                "tenant_id": tenant_id,
                "credential": "enr_provider_secret",
                "approved_by": "key:admin",
                "approved_at": 1.0,
            },
        )

    return handler


# --- the happy path, and what it hands back ------------------------------------------------


def test_redeeming_mints_then_redeems_and_returns_the_provider_credential(console, monkeypatch):
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()
    restore = _gateway_responder(app, _ok_gateway())
    try:
        resp = _redeem(client)
    finally:
        restore()

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant_id"] == TENANT
    assert body["credential"] == "enr_provider_secret"
    assert ("POST", f"/tenants/{TENANT}/credentials") in app.state.catalog.calls
    assert not app.state.catalog.revoked


def test_the_operator_never_names_their_own_subject(console):
    """`provider_subject` is filled from the session, the rule ADR-0017 states and
    `routers/provider.py` already follows. A body field would let a console name someone else
    as the operator who enrolled — and the enrolment records that permanently."""
    client, app = console
    _seed_session(client, app, _provider_session(sub="u-real-operator"))
    app.state.catalog = _FakeCatalog()
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        seen.update(_json.loads(request.content))
        return _ok_gateway()(request)

    restore = _gateway_responder(app, handler)
    try:
        _redeem(client, provider_subject="u-someone-else")
    finally:
        restore()
    assert seen["provider_subject"] == "u-real-operator"
    assert seen["catalog_url"] == CATALOG_URL


# --- the two failures that would otherwise be silent ---------------------------------------


def test_a_tenant_mismatch_revokes_the_credential_and_enrols_nothing(console):
    """The operator's typo. ADR-0020 §7b would catch this later as a page at the tenant's first
    catalog call; here it is caught before the credential is ever installed."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()
    restore = _gateway_responder(app, _ok_gateway(tenant_id="t-somebody-else"))
    try:
        resp = _redeem(client)
    finally:
        restore()

    assert resp.status_code == 409
    assert resp.json()["detail"]["error_code"] == "ERR_ENROLMENT_TENANT_MISMATCH"
    assert app.state.catalog.revoked, "a credential minted for the wrong tenant must not survive"


def test_a_refused_redemption_revokes_the_credential_it_minted(console):
    """An expired or already-redeemed invitation. Without the compensation, the catalog's caller
    table fills with live credentials belonging to tenants that were never enrolled — which
    nothing else in the estate would ever attribute to anything."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()

    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "a valid invitation is required to redeem"})

    restore = _gateway_responder(app, refuse)
    try:
        resp = _redeem(client)
    finally:
        restore()

    assert resp.status_code == 401
    assert app.state.catalog.revoked


def test_an_unreachable_gateway_revokes_the_credential_too(console):
    """The ambiguous case: we cannot tell whether the enrolment was created before the
    connection failed. Revoking anyway is the safe direction — a dead catalog credential reads
    to the tenant as a named unavailable condition they can re-enrol out of, where a live one
    belonging to an unrecorded enrolment reads as nothing at all."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    restore = _gateway_responder(app, boom)
    try:
        resp = _redeem(client)
    finally:
        restore()

    assert resp.status_code == 502
    assert app.state.catalog.revoked


# --- authority -----------------------------------------------------------------------------


def test_enrolling_needs_provider_admin(console):
    client, app = console
    _seed_session(client, app, _provider_session(provider_scopes=["provider:monitor"]))
    app.state.catalog = _FakeCatalog()
    assert _redeem(client).status_code == 403


def test_a_tenant_session_cannot_reach_the_route_at_all(console):
    """Provider-plane by construction, like curation and assignment beside it."""
    client, app = console
    _seed_session(client, app, {"kind": "oidc", "plane": "tenant", "sub": "u-tenant-1", "role": "admin"})
    app.state.catalog = _FakeCatalog()
    assert _redeem(client).status_code in (403, 404)


@pytest.mark.parametrize("missing", ["code", "gateway_url", "tenant_id"])
def test_an_incomplete_enrolment_is_refused_before_anything_is_minted(console, missing):
    """Named, and refused before step 1 — a credential minted for an enrolment that could never
    proceed is the orphan case arriving by a different route."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()
    resp = _redeem(client, **{missing: ""})
    assert resp.status_code == 400
    assert missing in resp.json()["detail"]
    assert app.state.catalog.calls == []
