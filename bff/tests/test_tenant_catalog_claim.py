# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §4, slice 4 — the tenant-plane claim flow.

The claim itself is not a new gateway capability: it merges a catalog device type's current
version with the tenant-supplied host/credential and calls the gateway's existing
`POST /devices`, unmodified — `app.state.gateway`, faked the same way `test_elevated_routes.py`
fakes it. `app.state.catalog` is faked the same way `test_provider_catalog.py` fakes it.

Four properties carry this slice:

1. **Only what's assigned to THIS tenant is claimable** — an unassigned type 403s, never a
   500 or a silently-empty registration.
2. **The template/instance split holds** — the version's fields (transport, upstream_kind,
   auth_kind, spec_path) end up in the merged body; the tenant's own fields (hostname,
   base_url, credential) are never overridden by the type.
3. **`spec_url` is joined against the TENANT's base_url**, never the curator's — §1's whole
   reason `spec_path` is relative.
4. **A catalog outage recording the pin does not undo an already-successful registration** —
   it is surfaced as its own named audit outcome instead.
"""

from __future__ import annotations

import os
from typing import Optional

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import copy  # noqa: E402

from tests.gateway_contract import ContractGateway  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.catalog_client import CatalogUnavailable  # noqa: E402
from app.main import create_app  # noqa: E402

TENANT = "acme"

DEVICE_TYPE_DETAIL = {
    "id": "t1",
    "slug": "acme-sensor-x1",
    "name": "Acme Sensor X1",
    "latest_version": 1,
    "versions": [
        {
            "id": "v1",
            "device_type_id": "t1",
            "version": 1,
            "transport": "sse",
            "upstream_kind": "openapi",
            "upstream_transport": "http",
            "spec_path": "/openapi.json",
            "auth_kind": "api_key",
            "fingerprint_policy": "enforce",
            "changelog": None,
        }
    ],
}


@pytest.fixture
def console(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", TENANT)
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.setenv("CATALOG_SERVICE_URL", "http://catalog.internal")
    monkeypatch.setenv("CATALOG_API_TOKEN", "catalog-token")
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _login(client) -> None:
    assert client.post("/auth/login", json={"password": "admin-pw"}).status_code == 200


def _audited(app, action: str) -> list[dict]:
    rows = app.state.audit.read(tenant=TENANT, limit=200)
    return [r["content"] for r in reversed(rows) if r["content"] and r["content"]["action"] == action]


class _FakeCatalog:
    """Answers `GET /tenants/{t}/assignments` and `GET /device-types/{id}` from fixed
    payloads, and records every call made through it — including the claim-recording POST,
    so a test can assert it happened without a real catalog service."""

    def __init__(
        self,
        *,
        assigned: Optional[list[str]] = None,
        detail: Optional[dict] = None,
        upgrades: Optional[list[dict]] = None,
    ):
        self.assigned = assigned if assigned is not None else ["t1"]
        self.detail = detail if detail is not None else DEVICE_TYPE_DETAIL
        self.upgrades = upgrades if upgrades is not None else []
        self.calls: list[dict] = []
        self._raise_on: set[str] = set()

    def fail_on(self, path_prefix: str) -> None:
        self._raise_on.add(path_prefix)

    async def request(self, method, path, *, json=None):
        self.calls.append({"method": method, "path": path, "json": json})
        for prefix in self._raise_on:
            if path.startswith(prefix):
                raise CatalogUnavailable("catalog unreachable (test)")
        if path == f"/tenants/{TENANT}/assignments":
            device_types = [
                {"id": i, "slug": i, "name": i, "created_at": "2026-01-01T00:00:00Z", "latest_version": 1}
                for i in self.assigned
            ]
            return httpx.Response(200, json={"device_types": device_types})
        if path == f"/tenants/{TENANT}/upgrades":
            return httpx.Response(200, json={"offers": self.upgrades})
        if path == "/device-types/t1":
            return httpx.Response(200, json=self.detail)
        if path == "/device-types/t1/claims":
            return httpx.Response(201, json={"id": "c1"})
        return httpx.Response(404, json={"detail": "not found"})


def _attach_catalog(app, fake: _FakeCatalog) -> _FakeCatalog:
    app.state.catalog.request = fake.request
    return fake


class _FakeGateway:
    def __init__(self, *, status: int = 201, payload=None):
        self.status = status
        self.payload = payload if payload is not None else {"hostname": "sensor-01"}
        self.calls: list[dict] = []

    async def request(self, method, path, json=None, bearer=None, headers=None):
        self.calls.append({"method": method, "path": path, "json": json})
        return httpx.Response(self.status, json=self.payload)


def _attach_gateway(app, fake: _FakeGateway) -> _FakeGateway:
    app.state.gateway.request = fake.request
    return fake


# --- listing / detail ----------------------------------------------------------------


def test_tenant_catalog_lists_only_what_is_assigned(console):
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(assigned=["t1", "t2"]))

    resp = client.get("/api/catalog/device-types")

    assert resp.status_code == 200
    assert {d["id"] for d in resp.json()["device_types"]} == {"t1", "t2"}


def test_tenant_catalog_list_names_a_catalog_outage_rather_than_reading_as_empty(console):
    client, app = console
    _login(client)
    fake = _FakeCatalog()
    fake.fail_on("/tenants/")
    _attach_catalog(app, fake)

    resp = client.get("/api/catalog/device-types")

    assert resp.status_code == 503


def test_detail_404s_for_a_type_not_assigned_to_this_tenant(console):
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(assigned=["some-other-type"]))

    resp = client.get("/api/catalog/device-types/t1")

    assert resp.status_code == 404


def test_detail_relays_the_assigned_types_versions(console):
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog())

    resp = client.get("/api/catalog/device-types/t1")

    assert resp.status_code == 200
    assert resp.json()["versions"][0]["auth_kind"] == "api_key"


def test_missing_tenant_id_is_a_named_503_not_a_lookup_of_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.delenv("TENANT_ID", raising=False)
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()
    with TestClient(app) as client:
        _login(client)
        resp = client.get("/api/catalog/device-types")
    assert resp.status_code == 503


# --- claim -----------------------------------------------------------------------------


def test_claim_403s_for_an_unassigned_type(console):
    client, app = console
    _login(client)
    catalog = _attach_catalog(app, _FakeCatalog(assigned=["some-other-type"]))
    gateway = _attach_gateway(app, _FakeGateway())

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "sensor-01", "base_url": "https://sensor-01.local"})

    assert resp.status_code == 403
    assert gateway.calls == []
    assert not any(c["path"] == "/device-types/t1/claims" for c in catalog.calls)


def test_claim_merges_the_template_with_the_tenants_own_fields(console):
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog())
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post(
        "/api/catalog/t1/claim",
        json={
            "hostname": "sensor-01",
            "base_url": "https://sensor-01.local/api/",
            "auth": {"api_key": "s3cr3t"},
        },
    )

    assert resp.status_code == 201
    assert len(gateway.calls) == 1
    body = gateway.calls[0]["json"]
    # The tenant's own fields, untouched by the type.
    assert body["hostname"] == "sensor-01"
    assert body["base_url"] == "https://sensor-01.local/api/"
    assert body["auth"] == {"api_key": "s3cr3t"}
    # The type's template fields, not something the tenant supplied.
    assert body["transport"] == "sse"
    assert body["upstream_kind"] == "openapi"
    assert body["auth_type"] == "api_key"
    assert body["fingerprint_policy"] == "enforce"
    # Joined against the TENANT's base_url, not any curator-side URL.
    assert body["spec_url"] == "https://sensor-01.local/api/openapi.json"


def test_claim_omits_auth_entirely_when_the_type_needs_none(console):
    client, app = console
    _login(client)
    detail = {**DEVICE_TYPE_DETAIL, "versions": [{**DEVICE_TYPE_DETAIL["versions"][0], "auth_kind": "none"}]}
    _attach_catalog(app, _FakeCatalog(detail=detail))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "sensor-01", "base_url": "https://sensor-01.local", "auth": {"api_key": "ignored"}},
    )

    assert resp.status_code == 201
    assert "auth" not in gateway.calls[0]["json"]


def test_claim_records_the_pin_after_a_successful_registration(console):
    client, app = console
    _login(client)
    catalog = _attach_catalog(app, _FakeCatalog())
    _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "sensor-01", "base_url": "https://sensor-01.local"})

    assert resp.status_code == 201
    claim_calls = [c for c in catalog.calls if c["path"] == "/device-types/t1/claims"]
    assert claim_calls == [
        {
            "method": "POST",
            "path": "/device-types/t1/claims",
            "json": {"tenant_id": TENANT, "hostname": "sensor-01", "version": 1},
        }
    ]


def test_claim_does_not_record_a_pin_when_registration_itself_fails(console):
    client, app = console
    _login(client)
    catalog = _attach_catalog(app, _FakeCatalog())
    _attach_gateway(app, _FakeGateway(status=409, payload={"detail": "already registered"}))

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "sensor-01", "base_url": "https://sensor-01.local"})

    assert resp.status_code == 409
    assert not any(c["path"] == "/device-types/t1/claims" for c in catalog.calls)


def test_a_lost_pin_is_a_named_audit_outcome_not_a_silent_drop(console):
    """The device is already registered by the time the pin-recording call is made — a
    catalog outage there must not read as if the claim never happened."""
    client, app = console
    _login(client)
    catalog = _attach_catalog(app, _FakeCatalog())
    catalog.fail_on("/device-types/t1/claims")
    _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "sensor-01", "base_url": "https://sensor-01.local"})

    assert resp.status_code == 201  # the registration itself still succeeded
    lost = _audited(app, "device.claim.pin_unrecorded")
    assert len(lost) == 1
    assert lost[0]["outcome"] == "error"


def test_claim_requires_an_authenticated_admin_session(console):
    client, app = console
    _attach_catalog(app, _FakeCatalog())
    _attach_gateway(app, _FakeGateway())

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "sensor-01", "base_url": "https://sensor-01.local"})

    assert resp.status_code == 401


# --- upgrade offers --------------------------------------------------------------------


def test_upgrades_relays_the_offers_list(console):
    client, app = console
    _login(client)
    offer = {
        "hostname": "sensor-01",
        "device_type_id": "t1",
        "slug": "acme-x1",
        "claimed_version": 1,
        "current_version": 2,
        "diff": {"added": ["calibrate"], "removed": [], "changed": [], "breaking": False, "breaking_reasons": []},
    }
    _attach_catalog(app, _FakeCatalog(upgrades=[offer]))

    resp = client.get("/api/catalog/upgrades")

    assert resp.status_code == 200
    assert resp.json()["offers"] == [offer]


def test_upgrades_names_a_catalog_outage_rather_than_reading_as_no_offers(console):
    client, app = console
    _login(client)
    fake = _FakeCatalog()
    fake.fail_on("/tenants/")
    _attach_catalog(app, fake)

    resp = client.get("/api/catalog/upgrades")

    assert resp.status_code == 503


def test_upgrades_requires_an_authenticated_session(console):
    client, app = console
    _attach_catalog(app, _FakeCatalog())

    resp = client.get("/api/catalog/upgrades")

    assert resp.status_code == 401


def test_accept_upgrade_re_pins_without_touching_the_gateway(console):
    client, app = console
    _login(client)
    catalog = _attach_catalog(app, _FakeCatalog())
    gateway = _attach_gateway(app, _FakeGateway())

    resp = client.post("/api/catalog/upgrades/sensor-01/accept", json={"device_type_id": "t1", "version": 2})

    assert resp.status_code == 201
    assert gateway.calls == []  # no device mutation — this is catalog-side bookkeeping only
    pin_calls = [c for c in catalog.calls if c["path"] == "/device-types/t1/claims"]
    assert pin_calls == [
        {
            "method": "POST",
            "path": "/device-types/t1/claims",
            "json": {"tenant_id": TENANT, "hostname": "sensor-01", "version": 2},
        }
    ]
    records = _audited(app, "device.claim.upgrade_accepted")
    assert len(records) == 1


def test_accept_upgrade_requires_device_type_id_and_version(console):
    client, app = console
    _login(client)
    catalog = _attach_catalog(app, _FakeCatalog())

    resp = client.post("/api/catalog/upgrades/sensor-01/accept", json={})

    assert resp.status_code == 400
    assert catalog.calls == []


def test_accept_upgrade_requires_an_authenticated_admin_session(console):
    client, app = console
    _attach_catalog(app, _FakeCatalog())

    resp = client.post("/api/catalog/upgrades/sensor-01/accept", json={"device_type_id": "t1", "version": 2})

    assert resp.status_code == 401


# --- product facts the curator supplies (ADR-0020 §2) ---------------------------------------
#
# Where the API key goes and what the appliance tolerates are properties of the PRODUCT, not
# of anyone's deployment of it. The tenant was typing both from a vendor PDF; getting
# `api_key_name` wrong yields a 401 at first contact that reads like a bad key.
#
# The credential VALUE stays the tenant's half throughout — only its position is curated.


def _curated(**over) -> dict:
    version = {**DEVICE_TYPE_DETAIL["versions"][0], "auth_kind": "api_key", **over}
    return {**DEVICE_TYPE_DETAIL, "versions": [version]}


def test_the_curated_api_key_position_overrides_what_the_browser_sent(console):
    """Overridden, not merely defaulted. `transport` and `spec_path` already work this way —
    a curated fact is not something a claim form gets to contradict."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_curated(api_key_location="header", api_key_name="X-API-Key")))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post(
        "/api/catalog/t1/claim",
        json={
            "hostname": "sensor-01",
            "base_url": "https://sensor-01.local",
            "auth": {"api_key": "s3cr3t", "location": "query", "name": "wrong"},
        },
    )

    assert resp.status_code == 201
    auth = gateway.calls[0]["json"]["auth"]
    assert auth["location"] == "header" and auth["name"] == "X-API-Key"
    # The one part that is emphatically NOT curated.
    assert auth["api_key"] == "s3cr3t"


def test_a_version_that_never_said_leaves_the_tenants_answer_alone(console):
    """`None` is "the curator has not said" — a version predating these fields. Overwriting a
    working claim with a null would break every device type curated before them."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_curated(api_key_location=None, api_key_name=None)))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post(
        "/api/catalog/t1/claim",
        json={
            "hostname": "sensor-01",
            "base_url": "https://sensor-01.local",
            "auth": {"api_key": "s3cr3t", "location": "query", "name": "apikey"},
        },
    )

    auth = gateway.calls[0]["json"]["auth"]
    assert auth["location"] == "query" and auth["name"] == "apikey"


def test_the_recommended_rate_limit_fills_in_only_when_the_tenant_sent_nothing(console):
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_curated(recommended_rate_limit_rps=10.5)))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "sensor-01", "base_url": "https://sensor-01.local", "auth": {"api_key": "k"}},
    )

    assert gateway.calls[0]["json"]["rate_limit_rps"] == 10.5


def test_the_tenants_rate_limit_wins_over_the_recommendation(console):
    """It is a RECOMMENDATION. A provider enforcing a ceiling on the tenant's own gateway
    would reach across the plane boundary §2 keeps — so a tenant who lowers it is obeyed, and
    so is one who raises it."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_curated(recommended_rate_limit_rps=10.5)))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post(
        "/api/catalog/t1/claim",
        json={
            "hostname": "sensor-01",
            "base_url": "https://sensor-01.local",
            "auth": {"api_key": "k"},
            "rate_limit_rps": 2,
        },
    )

    assert gateway.calls[0]["json"]["rate_limit_rps"] == 2


# --- ADR-0020 §4c: who supplies the address ------------------------------------------


def _host_fixed_detail(**over) -> dict:
    """DEVICE_TYPE_DETAIL with §4c's declaration on its current version."""
    detail = copy.deepcopy(DEVICE_TYPE_DETAIL)
    version = detail["versions"][0]
    version["host_source"] = "provider_fixed"
    version["fixed_base_url"] = "https://svc.provider.example"
    version.update(over)
    return detail


def test_a_host_fixed_type_registers_against_the_curated_address(console):
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_host_fixed_detail()))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "svc-01", "auth": {"api_key": "s3cr3t"}})

    assert resp.status_code == 201, resp.text
    assert gateway.calls[0]["json"]["base_url"] == "https://svc.provider.example"


def test_the_tenant_still_supplies_the_credential_for_a_host_fixed_type(console):
    """§4c's whole point. A host-fixed type is NOT a §6 provider-operated service: the
    provider knows where it is and mints nothing, so the key is still the tenant's."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_host_fixed_detail()))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post("/api/catalog/t1/claim", json={"hostname": "svc-01", "auth": {"api_key": "s3cr3t"}})

    assert gateway.calls[0]["json"]["auth"]["api_key"] == "s3cr3t"


def test_a_tenant_supplied_address_is_refused_not_overridden(console):
    """The opposite of what happens to `api_key_location`, and the difference is the point:
    a guessed key position is noise the curator can correct, a different address is a
    disagreement about where the device is. Overriding silently would leave a tenant
    believing they had pointed the device somewhere they had not."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_host_fixed_detail()))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "svc-01", "base_url": "https://somewhere.else.example", "auth": {"api_key": "k"}},
    )

    assert resp.status_code == 400
    assert "supplies its own address" in resp.json()["detail"]
    assert gateway.calls == [], "nothing may be registered when the claim is refused"


def test_a_spec_path_joins_against_the_curated_address(console):
    """`spec_path` is relative to whatever base_url is in force. For a host-fixed type that
    is the curated one — joining against the tenant's (absent) address would produce a
    spec_url of the path alone."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_host_fixed_detail()))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post("/api/catalog/t1/claim", json={"hostname": "svc-01", "auth": {"api_key": "k"}})

    assert gateway.calls[0]["json"]["spec_url"] == "https://svc.provider.example/openapi.json"


def test_a_type_that_declares_a_fixed_host_and_curated_none_fails_loudly(console):
    """Unreachable through curation — refused at write time with a CHECK constraint behind
    it — but reachable through a row predating either. It must not register a device with
    no address."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog(detail=_host_fixed_detail(fixed_base_url=None)))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "svc-01", "auth": {"api_key": "k"}})

    assert resp.status_code == 502
    assert gateway.calls == []


def test_a_version_predating_4c_still_asks_the_tenant(console):
    """Every version curated before §4c has no `host_source` at all. Absent must read as
    'tenant', not as a missing declaration to fail on."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog())  # the unmodified fixture: no host_source key
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    resp = client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "sensor-01", "base_url": "https://sensor-01.local", "auth": {"api_key": "k"}},
    )

    assert resp.status_code == 201
    assert gateway.calls[0]["json"]["base_url"] == "https://sensor-01.local"


# --- what the gateway will actually accept -------------------------------------------


def test_an_openapi_claim_does_not_send_upstream_transport(console):
    """The gateway refuses `upstream_transport` on an openapi registration, and refuses it on
    the **presence of the key** rather than its value — so the catalog's own default of
    "http" is rejected exactly as a wrong value would be.

    Sending it unconditionally made every OpenAPI device type unclaimable, with a 400 naming
    a field the tenant never supplied. Nothing caught it because the fake gateway here
    accepts any body: this assertion is about what we SEND, which is the only half a test
    with a stubbed upstream can own.
    """
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog())
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "sensor-01", "base_url": "https://sensor-01.local", "auth": {"api_key": "k"}},
    )

    assert "upstream_transport" not in gateway.calls[0]["json"]


def test_an_mcp_claim_still_sends_it(console):
    """The direction that keeps the fix honest: mcp is the kind the field exists for, and
    dropping it there would break passthrough claims instead."""
    client, app = console
    _login(client)
    detail = copy.deepcopy(DEVICE_TYPE_DETAIL)
    detail["versions"][0].update({"upstream_kind": "mcp", "upstream_transport": "http", "spec_path": None})
    _attach_catalog(app, _FakeCatalog(detail=detail))
    gateway = _attach_gateway(app, _FakeGateway(status=201))

    client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "mcp-01", "base_url": "https://mcp-01.local", "auth": {"api_key": "k"}},
    )

    assert gateway.calls[0]["json"]["upstream_transport"] == "http"


# --- against a gateway that refuses what the real one refuses (LR-50) ------------------
#
# Everything above this line runs against `_FakeGateway`, which returns 201 for any body. That
# double is more permissive than any gateway that has ever run, and two 🔴 defects lived in the
# gap: LR-48 (no OpenAPI type was claimable at all) and LR-49 (no credential-bearing type is
# claimable on the posture ADR-0018 recommends). Both were found by deploying into a lab.
#
# These run the same claim path against `ContractGateway`, which enforces
# `registry/validation.py`'s refusals. They are the ongoing coverage that would have caught
# both at the moment they were written.


def test_a_claim_survives_the_real_registration_rules(console):
    """The regression test for LR-48. Against the permissive fake this passed while the
    feature was completely broken in every deployment."""
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog())
    gateway = _attach_gateway(app, ContractGateway())

    resp = client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "sensor-01", "base_url": "https://sensor-01.local", "auth": {"api_key": "k"}},
    )

    assert resp.status_code == 201, f"the gateway refused the claim: {gateway.refusals}"
    assert gateway.refusals == []


def test_an_mcp_claim_survives_them_too(console):
    client, app = console
    _login(client)
    detail = copy.deepcopy(DEVICE_TYPE_DETAIL)
    detail["versions"][0].update({"upstream_kind": "mcp", "upstream_transport": "http", "spec_path": None})
    _attach_catalog(app, _FakeCatalog(detail=detail))
    gateway = _attach_gateway(app, ContractGateway())

    resp = client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "mcp-01", "base_url": "https://mcp-01.local", "auth": {"api_key": "k"}},
    )

    assert resp.status_code == 201, f"the gateway refused the claim: {gateway.refusals}"


def test_the_contract_double_would_have_caught_lr48(console):
    """Guards the guard. A double that quietly stopped enforcing would leave the two tests
    above passing for the same reason the old fake did, so the refusal is asserted directly
    against a body carrying the field the gateway forbids."""
    from tests.gateway_contract import check_registration

    assert check_registration({"upstream_kind": "openapi", "upstream_transport": "http"}) is not None
    assert check_registration({"upstream_kind": "openapi"}) is None


def test_a_credential_bearing_claim_is_refused_where_references_are_required(console):
    """LR-49, pinned as the measured state rather than left to be rediscovered.

    This is not the desired behaviour — it is what the deployment ADR-0018 §1 recommends
    actually does today, and it will stay true until §2a's 2026-09-01 amendment becomes
    applicable (blocked on a NETWORKED resolver). Pinning it means the day that changes, this
    test fails and says so, instead of the limitation quietly outliving its cause.
    """
    client, app = console
    _login(client)
    _attach_catalog(app, _FakeCatalog())
    gateway = _attach_gateway(app, ContractGateway(require_references=True))

    resp = client.post(
        "/api/catalog/t1/claim",
        json={"hostname": "sensor-01", "base_url": "https://sensor-01.local", "auth": {"api_key": "k"}},
    )

    assert resp.status_code == 400
    assert "by reference" in str(gateway.refusals)


def test_an_auth_free_claim_still_works_where_references_are_required(console):
    """The other half of the measured state, and the reason §4c could be proven in the lab at
    all: with nothing inline to refuse, the gate does not apply."""
    client, app = console
    _login(client)
    detail = copy.deepcopy(DEVICE_TYPE_DETAIL)
    detail["versions"][0]["auth_kind"] = "none"
    _attach_catalog(app, _FakeCatalog(detail=detail))
    gateway = _attach_gateway(app, ContractGateway(require_references=True))

    resp = client.post("/api/catalog/t1/claim", json={"hostname": "relay-01", "base_url": "https://relay.local"})

    assert resp.status_code == 201, f"the gateway refused the claim: {gateway.refusals}"
