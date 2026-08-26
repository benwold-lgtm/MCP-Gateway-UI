# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Per-tenant gateway clients for the provider console (ADR-0021, scoped build).

Slice 1 gave the provider console a directory of tenants; this gives it a way to actually
reach each one. Today's single-tenant BFF has exactly one `GatewayClient`, built once at
startup from `Settings`. A provider console instead needs one *per tenant it can reach*,
built lazily (most deployments will not touch every known tenant on every boot) and cached
(never a fresh client per request, which would leak connections) — and never one client
shared across tenants, which is the same failure shape the per-device-TLS project found and
fixed on the *outbound trust* side; this is the mirror image, on the *destination* side.
"""

from __future__ import annotations

from types import SimpleNamespace

from .gateway_client import GatewayClient
from .tenant_registry import TenantEntry


def _read_token_file(path: str) -> str:
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


class TenantGatewayPool:
    def __init__(self, registry: dict[str, TenantEntry], *, gateway_api_prefix: str) -> None:
        self._registry = registry
        self._gateway_api_prefix = gateway_api_prefix
        self._clients: dict[str, GatewayClient] = {}

    def __contains__(self, tenant_id: str) -> bool:
        return tenant_id in self._registry

    def get(self, tenant_id: str) -> GatewayClient:
        """The gateway client for one tenant, building and caching it on first use.

        Raises ``KeyError`` for a tenant_id the registry doesn't name — callers translate
        that into a 404, never a 500: an operator naming an unknown tenant is a client
        error (a stale bookmark, a typo), not a server fault.
        """
        if tenant_id not in self._registry:
            raise KeyError(tenant_id)
        client = self._clients.get(tenant_id)
        if client is None:
            entry = self._registry[tenant_id]
            # A plain namespace carrying only the three attributes GatewayClient actually
            # reads — not a full Settings (which also has UI passwords, a session secret,
            # etc. that have nothing to do with one outbound connection), the same shape
            # `test_tenant_plane_routes.py` already uses to build one directly.
            client = GatewayClient(
                SimpleNamespace(
                    gateway_url=entry.gateway_url,
                    gateway_token=_read_token_file(entry.gateway_token_file),
                    gateway_api_prefix=self._gateway_api_prefix,
                )
            )
            self._clients[tenant_id] = client
        return client

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
