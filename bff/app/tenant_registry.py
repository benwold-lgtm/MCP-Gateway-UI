# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The provider console's tenant registry (ADR-0021, scoped build) — which tenants exist and
where each one's gateway lives.

ADR-0024 §2 names this concept ("the provider-side registry entry") as one of three things a
tenant's identifier backs, alongside its namespace and console subdomain, but never built it.
Populated by tenant provisioning fulfilment (ADR-0024 — a human or GitOps pipeline edits this
config after standing up a tenant's stack), never by the console itself: the console holding
write access to its own tenant directory is exactly the provisioning authority ADR-0024 §1
declines to give it.

Deliberately just a lookup, not an authorization list. Under ADR-0017 a tenant's own approval
is the only authority that decides whether a raised request goes anywhere, so a provider
operator is free to raise a request against any tenant this registry names — there is no
"entitled but unreachable" distinction to carry the way the pre-ADR-0017 estate list had to.
That mechanism (`PROVIDER_ENTITLEMENT_CLAIM`) was removed at ADR-0017 slice 6 and is not being
rebuilt; this replaces it with something simpler, not a renaming of it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class TenantEntry:
    tenant_id: str
    display_name: str
    gateway_url: str
    # Path to a file holding this tenant's gateway service credential (the same env-or-file
    # convention config.py's `_secret` already uses) — never the raw token. ADR-0024 §4:
    # secrets are a separate out-of-band package and never enter a committed config, and
    # this registry is exactly that committed config. Empty means no credential is sent,
    # which is a legitimate state (a dev/lab tenant gateway with no auth configured), not an
    # error — mirrors how an empty `gateway_token` already behaves for a single-tenant BFF.
    gateway_token_file: str = ""
    #: True for an entry learned from the catalog's tenant registry (ADR-0024 §11) rather than
    #: from `PROVIDER_TENANT_REGISTRY`. Its gateway credential is deliberately **not** carried
    #: here: it is held encrypted in the catalog and fetched when the tenant is actually
    #: contacted, never as part of a listing. A listing is a screen left open.
    from_catalog: bool = False


class TenantRegistryError(ValueError):
    """PROVIDER_TENANT_REGISTRY is set but malformed. Raised at startup, not discovered on
    the first request that needed an entry — the same fail-closed posture this codebase
    already takes for PROVIDER_GROUP_SCOPES and the mTLS device config."""


def load_tenant_registry(raw: str) -> dict[str, TenantEntry]:
    """Parse the registry from its raw JSON text.

    Empty input is a valid, empty registry — a provider deployment with no tenants
    configured yet, not a config error. A non-empty, malformed value fails loudly rather
    than silently becoming ``{}``, which would read as "no tenants" instead of "a typo".
    """
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise TenantRegistryError(f"PROVIDER_TENANT_REGISTRY is not valid JSON: {exc}") from exc
    if not isinstance(parsed, list):
        raise TenantRegistryError("PROVIDER_TENANT_REGISTRY must be a JSON array of tenant entries")

    entries: dict[str, TenantEntry] = {}
    required = ("tenant_id", "display_name", "gateway_url")
    optional = ("gateway_token_file",)
    for i, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise TenantRegistryError(f"PROVIDER_TENANT_REGISTRY[{i}] must be an object")
        missing = [k for k in required if not item.get(k)]
        if missing:
            raise TenantRegistryError(f"PROVIDER_TENANT_REGISTRY[{i}] is missing {missing}")
        if not all(isinstance(item[k], str) for k in required):
            raise TenantRegistryError(f"PROVIDER_TENANT_REGISTRY[{i}] fields must all be strings")
        if not all(isinstance(item[k], str) for k in optional if k in item):
            raise TenantRegistryError(f"PROVIDER_TENANT_REGISTRY[{i}] fields must all be strings")
        tenant_id = item["tenant_id"]
        if tenant_id in entries:
            raise TenantRegistryError(f"PROVIDER_TENANT_REGISTRY has a duplicate tenant_id: {tenant_id!r}")
        entries[tenant_id] = TenantEntry(
            tenant_id=tenant_id,
            display_name=item["display_name"],
            gateway_url=item["gateway_url"],
            gateway_token_file=item.get("gateway_token_file", ""),
        )
    return entries
