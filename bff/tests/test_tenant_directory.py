# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §11 — the estate is read from the catalog, with config as the floor.

§11 moved the provider's tenant registry out of `PROVIDER_TENANT_REGISTRY` because enrolment and
revocation are routine and in-band, and config can only change by a redeploy. What this module
tests is the part of that move most likely to be got wrong quietly: **what happens when the
catalog cannot be asked.**

An estate that emptied during a catalog outage would take the provider's ability to reach its
tenants with it, at exactly the moment they are most likely to need support. So a failed refresh
keeps the last known estate and says so, and only a refresh that actually succeeded is allowed
to remove anyone.
"""

from __future__ import annotations

import httpx
import pytest

from app.catalog_client import CatalogUnavailable
from app.gateway_pool import TenantGatewayPool, TenantUnreachable
from app.tenant_directory import TenantDirectory
from app.tenant_registry import TenantEntry

CONFIGURED = {
    "t-config": TenantEntry(tenant_id="t-config", display_name="From Config", gateway_url="http://cfg:8000"),
}


class _Catalog:
    configured = True

    def __init__(self, *, tenants=None, status=200, body=None, raises=False, credential="enr_secret"):
        self._tenants = tenants if tenants is not None else []
        self._status = status
        self._body = body
        self._raises = raises
        self._credential = credential
        self.paths: list[str] = []

    async def request(self, method, path, *, json=None):
        self.paths.append(path)
        if self._raises:
            raise CatalogUnavailable("no route to the catalog")
        if path == "/tenants":
            if self._body is not None:
                return httpx.Response(self._status, json=self._body)
            return httpx.Response(self._status, json={"tenants": self._tenants})
        if self._credential is None:
            return httpx.Response(404, json={"detail": "not enrolled"})
        return httpx.Response(200, json={"tenant_id": "t-1", "gateway_credential": self._credential})


def _row(tenant_id, display_name="Enrolled", gateway_url="http://enrolled:8000"):
    return {"tenant_id": tenant_id, "display_name": display_name, "gateway_url": gateway_url}


# --- the merge ------------------------------------------------------------------------------


async def test_an_unconfigured_catalog_serves_config_and_is_not_stale():
    """A console with no catalog is a supported arrangement, not a degraded one. Reporting it as
    stale would show a permanent outage warning to every provider that has not adopted
    enrolment — the audience §11 explicitly promised to leave alone."""

    class _Absent:
        configured = False

        async def request(self, *a, **kw):  # pragma: no cover - must never be called
            raise AssertionError("an unconfigured catalog must not be asked")

    directory = TenantDirectory(CONFIGURED)
    assert await directory.refresh(_Absent()) is True
    assert not directory.stale
    assert set(directory.entries()) == {"t-config"}


async def test_the_catalog_estate_is_merged_over_config():
    directory = TenantDirectory(CONFIGURED)
    assert await directory.refresh(_Catalog(tenants=[_row("t-enrolled")])) is True
    assert set(directory.entries()) == {"t-config", "t-enrolled"}
    assert directory.entries()["t-enrolled"].from_catalog is True
    assert directory.entries()["t-config"].from_catalog is False


async def test_the_catalog_wins_a_collision_with_config():
    """A tenant in both is one whose config entry predates its enrolment. Preferring the stale
    copy would silently route to a gateway URL the tenant has since moved from — and config is
    the half that cannot have changed since boot."""
    directory = TenantDirectory(
        {"t-1": TenantEntry(tenant_id="t-1", display_name="Old Name", gateway_url="http://old:8000")}
    )
    await directory.refresh(_Catalog(tenants=[_row("t-1", "New Name", "http://new:8000")]))
    entry = directory.entries()["t-1"]
    assert entry.display_name == "New Name" and entry.gateway_url == "http://new:8000"


async def test_a_withdrawn_tenant_disappears_on_the_next_refresh():
    """Revocation has to take effect without a redeploy — the whole argument for leaving
    config. A successful refresh replaces the enrolled set wholesale rather than merging into
    it, because a tenant the catalog no longer lists has been withdrawn."""
    directory = TenantDirectory({})
    await directory.refresh(_Catalog(tenants=[_row("t-1"), _row("t-2")]))
    assert set(directory.entries()) == {"t-1", "t-2"}
    await directory.refresh(_Catalog(tenants=[_row("t-1")]))
    assert set(directory.entries()) == {"t-1"}


# --- what an outage must not do -------------------------------------------------------------


async def test_an_unreachable_catalog_keeps_the_last_known_estate_and_says_so():
    directory = TenantDirectory(CONFIGURED)
    await directory.refresh(_Catalog(tenants=[_row("t-enrolled")]))

    assert await directory.refresh(_Catalog(raises=True)) is False
    assert set(directory.entries()) == {"t-config", "t-enrolled"}, "an outage must not empty the estate"
    assert directory.stale


@pytest.mark.parametrize(
    "catalog",
    [
        _Catalog(status=500, body={"detail": "boom"}),
        _Catalog(body={"unexpected": "shape"}),
        _Catalog(body=["not", "an", "object"]),
    ],
    ids=["error-status", "missing-key", "wrong-type"],
)
async def test_an_answer_we_cannot_read_is_a_failure_not_an_empty_estate(catalog):
    """The "a default reads as a measurement" shape this project has paid for before: treating
    an unreadable 200 as zero tenants would drop the whole estate on a malformed response, and
    report it as the truth."""
    directory = TenantDirectory({})
    await directory.refresh(_Catalog(tenants=[_row("t-1")]))
    assert await directory.refresh(catalog) is False
    assert set(directory.entries()) == {"t-1"}
    assert directory.stale


async def test_recovering_clears_the_stale_flag():
    directory = TenantDirectory({})
    await directory.refresh(_Catalog(raises=True))
    assert directory.stale
    await directory.refresh(_Catalog(tenants=[_row("t-1")]))
    assert not directory.stale


# --- the credential is fetched, never listed ------------------------------------------------


async def test_the_estate_listing_never_carries_a_credential():
    """Mirrors the discipline the catalog's own repo states: a listing is a screen left open,
    and a credential should be fetched by the component that needs it, when it needs it."""
    catalog = _Catalog(tenants=[_row("t-1")])
    directory = TenantDirectory({})
    await directory.refresh(catalog)
    assert catalog.paths == ["/tenants"], "listing the estate must not fetch anyone's credential"
    assert not any("credential" in field for field in vars(directory.entries()["t-1"]))


async def test_an_unfetchable_credential_is_none_and_not_an_empty_string():
    """None means "we could not ask"; "" is a legitimate credential for a lab gateway with no
    auth. Conflating them turns an outage into a silent 401 against the tenant."""
    directory = TenantDirectory({})
    assert await directory.gateway_credential(_Catalog(raises=True), "t-1") is None
    assert await directory.gateway_credential(_Catalog(credential=None), "t-1") is None
    assert await directory.gateway_credential(_Catalog(credential=""), "t-1") == ""


# --- the pool -------------------------------------------------------------------------------


async def test_the_pool_fetches_an_enrolled_tenants_credential_on_first_contact():
    catalog = _Catalog(tenants=[_row("t-1")])
    directory = TenantDirectory({})
    await directory.refresh(catalog)

    pool = TenantGatewayPool(directory, gateway_api_prefix="/v1", catalog=catalog)
    client = await pool.get("t-1")
    assert client._client.headers["authorization"] == "Bearer enr_secret"
    assert catalog.paths == ["/tenants", "/tenants/t-1/gateway-credential"]


async def test_a_tenant_whose_credential_cannot_be_fetched_is_named_not_silently_unauthenticated():
    """Sending no credential to a gateway that wants one produces a 401 the operator reads as
    "my authority was refused", when the truth is "the catalog could not be asked"."""
    directory = TenantDirectory({})
    await directory.refresh(_Catalog(tenants=[_row("t-1")]))
    pool = TenantGatewayPool(directory, gateway_api_prefix="/v1", catalog=_Catalog(credential=None))
    with pytest.raises(TenantUnreachable):
        await pool.get("t-1")


async def test_invalidate_drops_the_cached_client_so_a_new_credential_is_picked_up():
    """Re-enrolling issues a new credential for the same gateway. Without this the pool keeps
    presenting the old one — working right up until it is revoked, then failing for a reason
    nothing in the process connects to the enrolment that caused it."""
    catalog = _Catalog(tenants=[_row("t-1")], credential="first")
    directory = TenantDirectory({})
    await directory.refresh(catalog)
    pool = TenantGatewayPool(directory, gateway_api_prefix="/v1", catalog=catalog)

    first = await pool.get("t-1")
    assert await pool.get("t-1") is first

    catalog._credential = "second"
    pool.invalidate("t-1")
    rebuilt = await pool.get("t-1")
    assert rebuilt is not first
    assert rebuilt._client.headers["authorization"] == "Bearer second"


async def test_a_config_tenant_never_asks_the_catalog_for_anything():
    """The floor keeps working exactly as it did — no catalog call, no new failure mode for a
    provider that has not adopted enrolment."""
    catalog = _Catalog()
    pool = TenantGatewayPool(TenantDirectory(CONFIGURED), gateway_api_prefix="/v1", catalog=catalog)
    await pool.get("t-config")
    assert catalog.paths == []
