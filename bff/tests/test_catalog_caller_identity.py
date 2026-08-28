# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0020 §7a: a tenant BFF refuses a catalog credential that is not its own tenant's.

The catalog service enforces the tenant from the credential, so a tenant console configured
with the *wrong tenant's* token is refused there. The case it cannot see is a tenant console
configured with the **provider's** token: that request authenticates correctly, as the
provider, and every other tenant's catalog data is in reach. Nothing in §7a's caller table
catches it, because from the catalog's side there is nothing wrong — the credential is exactly
what it claims to be, in the wrong building.

This is where that is closed, so these tests are the only proof it is closed anywhere.
"""

from __future__ import annotations

import httpx
import pytest

from app.catalog_client import CatalogClient, CatalogMisconfigured, CatalogUnavailable
from app.config import load_settings

TENANT = "t-ours"


def _client(monkeypatch, whoami: object, *, provider_console: bool = False, calls: list | None = None):
    """A `CatalogClient` whose transport answers `/whoami` with `whoami` and records calls.

    `whoami` is either a dict (answered as a 200 JSON body), an int (answered as that status
    with no body) or an `httpx.HTTPError` instance to raise.
    """
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.setenv("CATALOG_SERVICE_URL", "http://catalog.internal")
    monkeypatch.setenv("CATALOG_API_TOKEN", "some-token")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true" if provider_console else "false")
    if provider_console:
        # A provider console is defined by its second IdP; the rest of those settings are not
        # exercised here and the loader tolerates them being absent.
        monkeypatch.setenv("PROVIDER_OIDC_ISSUER", "https://provider.idp.invalid")

    recorded = calls if calls is not None else []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append(f"{request.method} {request.url.path}")
        if request.url.path == "/whoami":
            if isinstance(whoami, httpx.HTTPError):
                raise whoami
            if isinstance(whoami, int):
                return httpx.Response(whoami)
            return httpx.Response(200, json=whoami)
        return httpx.Response(200, json={"device_types": []})

    client = CatalogClient(load_settings())
    client._client = httpx.AsyncClient(
        base_url="http://catalog.internal",
        transport=httpx.MockTransport(handler),
    )
    return client, recorded


@pytest.mark.asyncio
async def test_a_matching_tenant_credential_is_used(monkeypatch):
    client, calls = _client(monkeypatch, {"kind": "tenant", "tenant_id": TENANT})
    resp = await client.request("GET", f"/tenants/{TENANT}/assignments")
    assert resp.status_code == 200
    assert calls == ["GET /whoami", f"GET /tenants/{TENANT}/assignments"]


@pytest.mark.asyncio
async def test_the_check_is_made_once_not_per_request(monkeypatch):
    client, calls = _client(monkeypatch, {"kind": "tenant", "tenant_id": TENANT})
    await client.request("GET", f"/tenants/{TENANT}/assignments")
    await client.request("GET", f"/tenants/{TENANT}/upgrades")
    assert calls.count("GET /whoami") == 1


@pytest.mark.asyncio
async def test_the_providers_credential_in_a_tenant_console_is_refused(monkeypatch):
    """The whole point. This is the configuration §7a warns deploying phase 1 would produce,
    and the one the catalog itself cannot detect."""
    client, calls = _client(monkeypatch, {"kind": "provider", "tenant_id": None})
    with pytest.raises(CatalogMisconfigured):
        await client.request("GET", f"/tenants/{TENANT}/assignments")
    # The real request was never made — refused before reaching the catalog, not after.
    assert calls == ["GET /whoami"]


@pytest.mark.asyncio
async def test_another_tenants_credential_is_refused(monkeypatch):
    client, _ = _client(monkeypatch, {"kind": "tenant", "tenant_id": "t-somebody-else"})
    with pytest.raises(CatalogMisconfigured):
        await client.request("GET", f"/tenants/{TENANT}/assignments")


@pytest.mark.asyncio
async def test_a_refusal_sticks_without_asking_again(monkeypatch):
    """A wrong credential is a deployment fact, not a transient one: re-probing on every
    request would turn a misconfiguration into a per-request round trip and change nothing."""
    client, calls = _client(monkeypatch, {"kind": "provider", "tenant_id": None})
    for _ in range(3):
        with pytest.raises(CatalogMisconfigured):
            await client.request("GET", f"/tenants/{TENANT}/assignments")
    assert calls.count("GET /whoami") == 1


@pytest.mark.asyncio
async def test_an_unreachable_catalog_is_unavailable_not_misconfigured(monkeypatch):
    """Told apart deliberately: "could not check" and "checked and it was wrong" are different
    conditions, and collapsing them would either brick a correctly-configured console during an
    outage or quietly excuse a real mismatch."""
    client, _ = _client(monkeypatch, httpx.ConnectError("no route"))
    with pytest.raises(CatalogUnavailable) as exc:
        await client.request("GET", f"/tenants/{TENANT}/assignments")
    assert not isinstance(exc.value, CatalogMisconfigured)


@pytest.mark.asyncio
async def test_an_unmade_check_is_retried(monkeypatch):
    """A failed probe leaves the question open rather than answering it pessimistically, so a
    console that started during a catalog outage recovers on its own."""
    calls: list = []
    client, _ = _client(monkeypatch, httpx.ConnectError("no route"), calls=calls)
    with pytest.raises(CatalogUnavailable):
        await client.request("GET", f"/tenants/{TENANT}/assignments")
    with pytest.raises(CatalogUnavailable):
        await client.request("GET", f"/tenants/{TENANT}/assignments")
    assert calls.count("GET /whoami") == 2


@pytest.mark.asyncio
async def test_a_provider_console_is_not_checked_against_a_tenant(monkeypatch):
    """The provider console legitimately holds the privileged credential and speaks for no
    single tenant, so there is nothing for it to match against and no probe to make."""
    client, calls = _client(monkeypatch, {"kind": "provider", "tenant_id": None}, provider_console=True)
    resp = await client.request("GET", "/device-types")
    assert resp.status_code == 200
    assert "GET /whoami" not in calls
