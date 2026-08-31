# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §10 and §11 — the provider console redeems a tenant's invitation.

Four steps that were nine manual ones: record the tenant and mint its catalog credential (one
transaction, §11), redeem the invitation against the tenant's gateway, verify the gateway
reports the tenant we minted for, and record the credential it returned. What is tested hardest
here is not the happy path but the ways it can go wrong without anyone noticing:

* an **enrolment orphaned** by a redemption that failed after minting — a live credential and a
  registry entry for a tenant that was never enrolled, which nothing else in the estate would
  ever attribute;
* a **tenant mismatch**, where an operator's typo mints for tenant A and installs in tenant B.
  ADR-0020 §7b catches that later, at the tenant's first catalog call, as a page. This catches
  it before the credential is ever installed;
* the **secret escaping**: §11's whole point is that the provider's credential is recorded, not
  handed to an operator to place. A response that still carried it would leave the manual step
  in the flow while the record claimed it was gone.
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
PUBLIC_CATALOG_URL = "https://catalog.provider.example"
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
    # Distinct from CATALOG_SERVICE_URL on purpose, in the fixture as well as in the tests
    # that assert on it: if the two were equal here, the bug this pair exists to prevent —
    # handing a tenant the address only the provider can resolve — would be invisible.
    monkeypatch.setenv("PUBLIC_CATALOG_URL", PUBLIC_CATALOG_URL)
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
    """Answers the catalog calls this flow makes and records every one with its body, so a test
    can assert an orphaned enrolment was actually withdrawn — and that the provider's credential
    was actually recorded — rather than merely intended to be."""

    configured = True

    def __init__(self, *, enrol_status: int = 201, record_status: int = 200) -> None:
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[tuple[str, str, dict | None]] = []
        self._enrol_status = enrol_status
        self._record_status = record_status

    async def request(self, method: str, path: str, *, json=None):
        self.calls.append((method, path))
        self.bodies.append((method, path, json))
        if method == "POST" and path == "/tenants":
            return httpx.Response(
                self._enrol_status,
                json={"tenant_id": TENANT, "credential_id": CREDENTIAL_ID, "credential": "cat_secret"},
            )
        if method == "PUT":
            return httpx.Response(self._record_status, json={"tenant_id": TENANT, "recorded": True})
        if method == "GET" and path == "/tenants":
            return httpx.Response(200, json={"tenants": [{"tenant_id": TENANT, "display_name": "Acme"}]})
        return httpx.Response(200, json={"tenant_id": TENANT, "removed": True, "credentials_revoked": 1})

    async def aclose(self) -> None:
        """The app's shutdown closes whatever is on `state.catalog`; a double that omitted this
        turned every test into a teardown error while still reporting the assertions passed."""

    @property
    def withdrawn(self) -> bool:
        """§11 makes ending a relationship one call: the registry entry and the credential go
        together. So the compensation this asserts is a single DELETE, not a credential revoke
        the caller would then have to follow with a registry edit."""
        return ("DELETE", f"/tenants/{TENANT}") in self.calls

    def body_of(self, method: str, path: str) -> dict:
        return next(body for m, p, body in self.bodies if m == method and p == path) or {}


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


def test_redeeming_enrols_the_tenant_and_records_the_credential_it_receives(console, monkeypatch):
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
    assert body["recorded"] is True

    # One call, one transaction in the catalog — not "mint a credential, then tell a human to
    # edit PROVIDER_TENANT_REGISTRY", which is the step §11 exists to remove.
    assert ("POST", "/tenants") in app.state.catalog.calls
    enrolled = app.state.catalog.body_of("POST", "/tenants")
    assert enrolled["tenant_id"] == TENANT and enrolled["gateway_url"] == GATEWAY_URL
    assert not app.state.catalog.withdrawn


def test_the_provider_credential_is_recorded_and_never_returned(console):
    """§11's point, stated as a test. The credential the tenant's gateway hands back is the one
    secret in this flow whose purpose is to be presented again later — so it goes into the
    registry, and a response still carrying it would leave the manual step in place while the
    record claimed it was gone."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()
    restore = _gateway_responder(app, _ok_gateway())
    try:
        resp = _redeem(client)
    finally:
        restore()

    recorded = app.state.catalog.body_of("PUT", f"/tenants/{TENANT}/gateway-credential")
    assert recorded["gateway_credential"] == "enr_provider_secret"
    assert recorded["enrolment_id"] == "e-1"
    assert "enr_provider_secret" not in resp.text
    assert "credential" not in resp.json()


def test_a_catalog_that_will_not_record_the_credential_does_not_withdraw(console):
    """The one failure that must NOT compensate. By this point the tenant's gateway holds a live
    enrolment; withdrawing would revoke the credential it is using while destroying our only
    copy of the one it just gave us. The tenant is left listed and unreachable — visible, and
    repairable by enrolling again — which §11 argues is strictly better than an invisible gap."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog(record_status=500)
    restore = _gateway_responder(app, _ok_gateway())
    try:
        resp = _redeem(client)
    finally:
        restore()

    assert resp.status_code == 502
    assert resp.json()["detail"]["error_code"] == "ERR_ENROLMENT_NOT_RECORDED"
    assert not app.state.catalog.withdrawn, "the tenant's live enrolment must not be torn down here"
    assert "enr_provider_secret" not in resp.text


def test_a_successful_enrolment_drops_any_cached_client_for_that_tenant(console):
    """Re-enrolling issues a NEW credential for the same gateway. A pool still holding the
    client it built from the old one would keep working until that credential was revoked, then
    fail for a reason nothing in this process would connect to the enrolment that caused it."""
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()
    invalidated: list[str] = []
    app.state.gateway_pool.invalidate = invalidated.append
    restore = _gateway_responder(app, _ok_gateway())
    try:
        _redeem(client)
    finally:
        restore()
    assert invalidated == [TENANT]


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
    # Was `== CATALOG_URL` until 2026-08-31, which pinned the defect in place: this line
    # asserted that the tenant is handed the address the PROVIDER dials. It passed for exactly
    # as long as the bug existed, and a test written to check that a client cannot spoof a
    # subject had quietly become the thing defending the wrong catalog address.
    assert seen["catalog_url"] == PUBLIC_CATALOG_URL


# --- the two failures that would otherwise be silent ---------------------------------------


def test_a_tenant_mismatch_withdraws_the_enrolment_and_leaves_nothing(console):
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
    assert app.state.catalog.withdrawn, "an enrolment recorded for the wrong tenant must not survive"


def test_a_refused_redemption_withdraws_the_enrolment_it_recorded(console):
    """An expired or already-redeemed invitation. Without the compensation, the catalog fills
    with registry entries and live credentials belonging to tenants that were never enrolled —
    which nothing else in the estate would ever attribute to anything."""
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
    assert app.state.catalog.withdrawn


def test_an_unreachable_gateway_withdraws_the_enrolment_too(console):
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
    assert app.state.catalog.withdrawn


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


# --- the address handed to the tenant is not the one we dial --------------------------------
#
# Found in the browser. A tenant enrolled through the console received
# `http://device-mcp-catalog:8100` as its catalog address — the provider's own in-cluster
# ClusterIP name — and every catalog read in that tenant's console then failed with
# "Temporary failure in name resolution", forever, while the enrolment reported success.
#
# The exact mirror of the tenant-side GATEWAY_URL / PUBLIC_GATEWAY_URL split: an address that
# is correct for the process holding it and meaningless to anyone else.


def _recording_gateway(seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        seen.append(_json.loads(request.content))
        return _ok_gateway()(request)

    return handler


def test_the_tenant_is_given_the_public_catalog_url_not_the_one_we_dial(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    app.state.catalog = _FakeCatalog()
    seen: list = []
    restore = _gateway_responder(app, _recording_gateway(seen))
    try:
        resp = _redeem(client)
    finally:
        restore()

    assert resp.status_code == 200, resp.text
    [handed] = seen
    assert handed["catalog_url"] == PUBLIC_CATALOG_URL
    assert handed["catalog_url"] != CATALOG_URL, "the tenant was handed the address WE dial"


def test_enrolment_is_refused_when_no_public_catalog_url_is_set(console, monkeypatch):
    """Refused, never defaulted. Falling back to CATALOG_SERVICE_URL produces an enrolment that
    looks completely successful and leaves the tenant permanently unable to reach the catalog —
    §10's step 9, which "fails quietly and reads as the catalog being down while it is
    healthy"."""
    monkeypatch.delenv("PUBLIC_CATALOG_URL", raising=False)
    app = create_app()
    with TestClient(app) as client:
        _seed_session(client, app, _provider_session())
        app.state.catalog = _FakeCatalog()
        resp = _redeem(client)

    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == "ERR_PUBLIC_CATALOG_URL_NOT_SET"
    # Refused BEFORE step 1, so there is no orphaned credential to compensate for.
    assert ("POST", "/tenants") not in app.state.catalog.calls
