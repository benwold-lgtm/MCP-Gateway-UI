# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §7b: this BFF declares which tenant it serves, and the catalog decides.

An earlier version of these tests exercised a client-side check — the BFF asked the catalog's
`/whoami` and decided for itself whether to proceed. §7b corrected that: a client-side gate on a
server-enforced property is the shape ADR-0017 §7b already found, and a check the client can
forget is a check that will be forgotten.

So what is tested here is narrower and, deliberately, weaker-looking: that the declaration is
sent on every request and cannot be omitted, and that the catalog's refusal becomes a named
condition rather than a raw 403. **The enforcement itself is proven in the gateway repo**
(`device_mcp_catalog/tests/test_declared_tenant.py`), which is the point of moving it there.
"""

from __future__ import annotations

import httpx
import pytest

from app.catalog_client import TENANT_HEADER, CatalogClient, CatalogMisconfigured, CatalogUnavailable
from app.config import load_settings

TENANT = "t-ours"


def _client(monkeypatch, responder=None, *, provider_console: bool = False):
    """A `CatalogClient` over a mock transport that records the headers it was given."""
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.setenv("CATALOG_SERVICE_URL", "http://catalog.internal")
    monkeypatch.setenv("CATALOG_API_TOKEN", "some-token")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true" if provider_console else "false")
    if provider_console:
        monkeypatch.setenv("PROVIDER_OIDC_ISSUER", "https://provider.idp.invalid")

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if responder is not None:
            return responder(request)
        return httpx.Response(200, json={"device_types": []})

    client = CatalogClient(load_settings())
    client._client = httpx.AsyncClient(
        base_url="http://catalog.internal",
        headers=client._client.headers,
        transport=httpx.MockTransport(handler),
    )
    return client, seen


def _refusal(code: str):
    return lambda request: httpx.Response(403, json={"detail": {"error_code": code, "message": "no"}})


# --- the declaration is sent, and cannot be omitted -----------------------------------------


@pytest.mark.asyncio
async def test_every_request_declares_this_deployments_tenant(monkeypatch):
    client, seen = _client(monkeypatch)
    await client.request("GET", f"/tenants/{TENANT}/assignments")
    await client.request("POST", "/device-types/x/claims", json={"tenant_id": TENANT})
    assert [r.headers.get(TENANT_HEADER) for r in seen] == [TENANT, TENANT]


@pytest.mark.asyncio
async def test_the_declaration_is_on_the_client_not_the_call(monkeypatch):
    """Set once on the long-lived client, so no request path can forget it. A per-call header
    would be one `request()` overload away from a call that quietly declares nothing — and a
    caller that declares nothing is refused, so the failure would be a broken console rather
    than an open door, but broken is still not the goal."""
    client, _ = _client(monkeypatch)
    assert client._client.headers.get(TENANT_HEADER) == TENANT


@pytest.mark.asyncio
async def test_a_provider_console_declares_nothing(monkeypatch):
    """It holds the privileged credential legitimately and speaks for no single tenant. A
    declaration arriving with the provider's credential is itself the misdelivery signal, so
    sending one here would make the provider console page the on-call every request."""
    client, seen = _client(monkeypatch, provider_console=True)
    await client.request("GET", "/device-types")
    assert TENANT_HEADER not in seen[0].headers


# --- the catalog's refusal becomes a named condition ----------------------------------------


@pytest.mark.asyncio
async def test_a_misdelivery_refusal_is_named(monkeypatch):
    client, _ = _client(monkeypatch, _refusal("ERR_CREDENTIAL_MISDELIVERY"))
    with pytest.raises(CatalogMisconfigured):
        await client.request("GET", f"/tenants/{TENANT}/assignments")


@pytest.mark.asyncio
async def test_an_undeclared_refusal_is_named_too(monkeypatch):
    """Both §7b codes mean the same thing from here — this deployment's credential and its
    identity do not agree, and no request will succeed until that is fixed."""
    client, _ = _client(monkeypatch, _refusal("ERR_TENANT_NOT_DECLARED"))
    with pytest.raises(CatalogMisconfigured):
        await client.request("GET", f"/tenants/{TENANT}/assignments")


@pytest.mark.asyncio
async def test_an_ordinary_403_is_passed_through_not_renamed(monkeypatch):
    """A provider-only route refusing a tenant caller is §7a working correctly, not a
    misconfigured deployment. Collapsing the two would make every scope refusal look like a
    provisioning emergency."""
    client, _ = _client(monkeypatch, lambda r: httpx.Response(403, json={"detail": "this route is provider-only"}))
    resp = await client.request("GET", "/device-types")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_a_403_with_no_json_body_is_passed_through(monkeypatch):
    client, _ = _client(monkeypatch, lambda r: httpx.Response(403, text="nope"))
    resp = await client.request("GET", "/device-types")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_an_unreachable_catalog_is_unavailable_not_misconfigured(monkeypatch):
    """Still told apart: "could not reach it" and "it refused this credential" are different
    conditions, and collapsing them would report a provisioning fault during every outage."""

    def boom(request):
        raise httpx.ConnectError("no route")

    client, _ = _client(monkeypatch, boom)
    with pytest.raises(CatalogUnavailable) as exc:
        await client.request("GET", f"/tenants/{TENANT}/assignments")
    assert not isinstance(exc.value, CatalogMisconfigured)


@pytest.mark.asyncio
async def test_the_refusal_is_not_cached(monkeypatch):
    """The old client-side check remembered its verdict, which is what a client-side check must
    do to be affordable. With the decision on the server there is no verdict to cache — every
    request is checked, so §7b's open question about *when* to re-check answers itself."""
    client, seen = _client(monkeypatch, _refusal("ERR_CREDENTIAL_MISDELIVERY"))
    for _ in range(3):
        with pytest.raises(CatalogMisconfigured):
            await client.request("GET", f"/tenants/{TENANT}/assignments")
    assert len(seen) == 3
