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
from .tenant_directory import TenantDirectory


def _read_token_file(path: str) -> str:
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


class TenantUnreachable(RuntimeError):
    """The tenant is enrolled, but its gateway credential could not be fetched (ADR-0024 §11).

    A named condition rather than an empty credential, because those are different facts with
    the same symptom: sending no credential to a gateway that wants one produces a 401 the
    operator would read as "my authority was refused" when the truth is "the catalog could not
    be asked". Callers turn this into a 503 that says which.
    """


class TenantGatewayPool:
    def __init__(self, directory: TenantDirectory, *, gateway_api_prefix: str, catalog=None) -> None:
        self._directory = directory
        self._gateway_api_prefix = gateway_api_prefix
        self._catalog = catalog
        self._clients: dict[str, GatewayClient] = {}

    def __contains__(self, tenant_id: str) -> bool:
        return tenant_id in self._directory

    async def get(self, tenant_id: str) -> GatewayClient:
        """The gateway client for one tenant, building and caching it on first use.

        Async since ADR-0024 §11: a tenant learned from the catalog holds its credential there,
        encrypted, and it is fetched here — when the tenant is actually contacted — rather than
        as a field on the estate listing. That is the same discipline the catalog's own repo
        applies, carried across the plane boundary instead of stopping at it.

        Raises ``KeyError`` for a tenant_id the directory doesn't name — callers translate
        that into a 404, never a 500: an operator naming an unknown tenant is a client
        error (a stale bookmark, a typo), not a server fault.
        """
        entry = self._directory.get(tenant_id)
        client = self._clients.get(tenant_id)
        if client is None:
            # A plain namespace carrying only the three attributes GatewayClient actually
            # reads — not a full Settings (which also has UI passwords, a session secret,
            # etc. that have nothing to do with one outbound connection), the same shape
            # `test_tenant_plane_routes.py` already uses to build one directly.
            client = GatewayClient(
                SimpleNamespace(
                    gateway_url=entry.gateway_url,
                    gateway_token=await self._token_for(tenant_id, entry),
                    gateway_api_prefix=self._gateway_api_prefix,
                )
            )
            self._clients[tenant_id] = client
        return client

    async def _token_for(self, tenant_id: str, entry) -> str:
        if not entry.from_catalog:
            return _read_token_file(entry.gateway_token_file)
        if self._catalog is None:
            raise TenantUnreachable(
                f"tenant {tenant_id!r} was enrolled through the catalog, but this console has "
                "no catalog configured to fetch its gateway credential from"
            )
        credential = await self._directory.gateway_credential(self._catalog, tenant_id)
        if credential is None:
            raise TenantUnreachable(f"the catalog could not be asked for tenant {tenant_id!r}'s gateway credential")
        return credential

    def invalidate(self, tenant_id: str) -> None:
        """Drop the cached client for one tenant, so the next contact rebuilds it.

        Re-enrolling a tenant issues a *new* credential for the same gateway, and a pool that
        cached a client at boot would keep presenting the old one — succeeding until the moment
        the old enrolment is revoked, then failing for a reason nothing in this process would
        connect to the enrolment that happened. Closing the stale client is left to `aclose()`;
        dropping it from the map is what the correctness argument needs.
        """
        self._clients.pop(tenant_id, None)

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
