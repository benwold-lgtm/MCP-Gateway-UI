# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0021 (scoped) slice 1 — the provider console's tenant registry loader.

Fail-closed on anything malformed rather than silently degrading to an empty directory,
which would read as "no tenants configured" instead of "a typo in PROVIDER_TENANT_REGISTRY".
"""

from __future__ import annotations

import json

import pytest

from app.tenant_registry import TenantEntry, TenantRegistryError, load_tenant_registry


def test_empty_string_is_a_valid_empty_registry():
    assert load_tenant_registry("") == {}
    assert load_tenant_registry("   ") == {}


def test_valid_registry_parses():
    raw = """
    [
        {"tenant_id": "t-1", "display_name": "Tenant One", "gateway_url": "http://t1:8000"},
        {"tenant_id": "t-2", "display_name": "Tenant Two", "gateway_url": "http://t2:8000"}
    ]
    """
    registry = load_tenant_registry(raw)
    assert registry == {
        "t-1": TenantEntry(tenant_id="t-1", display_name="Tenant One", gateway_url="http://t1:8000"),
        "t-2": TenantEntry(tenant_id="t-2", display_name="Tenant Two", gateway_url="http://t2:8000"),
    }


def test_malformed_json_is_refused():
    with pytest.raises(TenantRegistryError, match="not valid JSON"):
        load_tenant_registry("{not json")


def test_a_json_object_instead_of_an_array_is_refused():
    with pytest.raises(TenantRegistryError, match="must be a JSON array"):
        load_tenant_registry('{"tenant_id": "t-1"}')


def test_a_non_object_entry_is_refused():
    with pytest.raises(TenantRegistryError, match="must be an object"):
        load_tenant_registry('["t-1"]')


@pytest.mark.parametrize("missing_field", ["tenant_id", "display_name", "gateway_url"])
def test_a_missing_field_is_refused(missing_field):
    entry = {"tenant_id": "t-1", "display_name": "Tenant One", "gateway_url": "http://t1:8000"}
    del entry[missing_field]
    with pytest.raises(TenantRegistryError, match="missing"):
        load_tenant_registry(json.dumps([entry]))


def test_a_non_string_field_is_refused():
    raw = '[{"tenant_id": "t-1", "display_name": "Tenant One", "gateway_url": 8000}]'
    with pytest.raises(TenantRegistryError, match="must all be strings"):
        load_tenant_registry(raw)


def test_a_duplicate_tenant_id_is_refused():
    raw = """
    [
        {"tenant_id": "t-1", "display_name": "Tenant One", "gateway_url": "http://t1:8000"},
        {"tenant_id": "t-1", "display_name": "Tenant One Again", "gateway_url": "http://t1b:8000"}
    ]
    """
    with pytest.raises(TenantRegistryError, match="duplicate tenant_id"):
        load_tenant_registry(raw)
