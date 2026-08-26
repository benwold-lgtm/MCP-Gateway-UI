# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0021 (scoped) slice 2 — the provider console's per-tenant gateway client pool."""

from __future__ import annotations

import pytest

from app.gateway_pool import TenantGatewayPool
from app.tenant_registry import TenantEntry

REGISTRY = {
    "t-1": TenantEntry(tenant_id="t-1", display_name="Tenant One", gateway_url="http://t1:8000"),
    "t-2": TenantEntry(tenant_id="t-2", display_name="Tenant Two", gateway_url="http://t2:8000"),
}


def test_unknown_tenant_raises_key_error():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v1")
    with pytest.raises(KeyError):
        pool.get("no-such-tenant")


def test_contains_reflects_the_registry():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v1")
    assert "t-1" in pool
    assert "no-such-tenant" not in pool


def test_each_tenant_gets_its_own_client_pointed_at_its_own_gateway_url():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v1")
    t1 = pool.get("t-1")
    t2 = pool.get("t-2")
    assert t1 is not t2
    assert str(t1._client.base_url) == "http://t1:8000"
    assert str(t2._client.base_url) == "http://t2:8000"


def test_the_same_tenant_returns_the_cached_client_not_a_fresh_one():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v1")
    first = pool.get("t-1")
    second = pool.get("t-1")
    assert first is second


def test_gateway_api_prefix_is_shared_across_every_tenant():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v2")
    assert pool.get("t-1")._prefix == "/v2"
    assert pool.get("t-2")._prefix == "/v2"


def test_no_token_file_means_no_authorization_header():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v1")
    client = pool.get("t-1")
    assert "authorization" not in {k.lower() for k in client._client.headers}


def test_a_token_file_is_read_into_the_authorization_header(tmp_path):
    token_file = tmp_path / "t1-token"
    token_file.write_text("SECRET-TOKEN-123\n")
    registry = {
        "t-1": TenantEntry(
            tenant_id="t-1",
            display_name="Tenant One",
            gateway_url="http://t1:8000",
            gateway_token_file=str(token_file),
        ),
    }
    pool = TenantGatewayPool(registry, gateway_api_prefix="/v1")
    client = pool.get("t-1")
    assert client._client.headers["authorization"] == "Bearer SECRET-TOKEN-123"


def test_a_missing_token_file_is_treated_as_no_token_not_an_error(tmp_path):
    registry = {
        "t-1": TenantEntry(
            tenant_id="t-1",
            display_name="Tenant One",
            gateway_url="http://t1:8000",
            gateway_token_file=str(tmp_path / "does-not-exist"),
        ),
    }
    pool = TenantGatewayPool(registry, gateway_api_prefix="/v1")
    client = pool.get("t-1")
    assert "authorization" not in {k.lower() for k in client._client.headers}


async def test_aclose_closes_every_built_client_but_not_unbuilt_ones():
    pool = TenantGatewayPool(REGISTRY, gateway_api_prefix="/v1")
    t1 = pool.get("t-1")
    assert not t1._client.is_closed
    await pool.aclose()
    assert t1._client.is_closed
    # t-2 was never touched, so building it now is still possible (aclose didn't reach
    # into the registry and poison every entry, only the clients actually constructed).
    t2 = pool.get("t-2")
    assert not t2._client.is_closed
