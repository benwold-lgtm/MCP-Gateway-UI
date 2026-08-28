# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Thin async client to the catalog service (ADR-0020), carrying its bearer token.

Mirrors `gateway_client.py`'s shape — one long-lived `httpx.AsyncClient`, the credential
attached in exactly one place — and there is still no per-request bearer to swap in, because
the credential identifies the *deployment*, not the logged-in human.

**What that credential means changed in ADR-0020 §7a.** It used to be one shared token for the
catalog's single caller. It is now a caller-class credential: the privileged provider token on
a provider-console BFF, and **that tenant's own token** on a tenant-plane BFF. The two are
never the same value, and the catalog refuses to start if they are.

The catalog enforces the tenant from the credential, so a tenant BFF configured with the wrong
*tenant's* token is refused there. The case it could not see on its own is a tenant BFF
configured with the **provider's** token — that request authenticates correctly, as the
provider, with every tenant's data in reach.

**§7b closes that on the server, not here.** This client sends `X-Catalog-Tenant` — the tenant
this deployment believes it serves — on every request, and the catalog refuses when the
declaration disagrees with the credential. An earlier version of this file asked `/whoami` and
decided client-side; that was a client-side gate on a server-enforced property, the same
wrong-layer error ADR-0020 §7a had just corrected one component along. What is left here is
sending the declaration and translating the server's refusal into a named condition — a client
that forgot to send it would simply be refused, which is the property that matters.

ADR-0020 §7: the catalog's unavailability must be a **named condition**, never inferred from
an empty list — a provider console showing no device types because the catalog is down must
not look like a provider who has curated none. `CatalogUnavailable` is what lets a route tell
the two apart; see `routers/catalog.py`.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .config import Settings

logger = logging.getLogger(__name__)

#: The §7b declaration header. Must match `device_mcp_catalog.app.auth.TENANT_HEADER` in the
#: gateway repository — two constants across a process boundary, which is exactly the shape
#: that drifts, so the catalog answers a request missing it with a named error rather than a
#: generic 403.
TENANT_HEADER = "X-Catalog-Tenant"

#: The catalog's §7b refusal codes. Both mean the same thing from here — this deployment's
#: credential and its identity do not agree, and no request will succeed until that is fixed —
#: so both map to `CatalogMisconfigured`. They stay distinguishable in the log line because
#: they point an operator at different fixes: the wrong secret, or an un-updated console.
_MISDELIVERY_CODES = ("ERR_CREDENTIAL_MISDELIVERY", "ERR_TENANT_NOT_DECLARED")


class CatalogUnavailable(Exception):
    """The catalog service is unreachable, or this BFF has no token configured for it."""


class CatalogMisconfigured(CatalogUnavailable):
    """This BFF's catalog credential is not the one this deployment should hold (§7a/§7b).

    A subclass of `CatalogUnavailable` so that every existing route already answers it as the
    named 503 condition rather than a 500 — the catalog genuinely is unusable from here, and
    the reason is stated rather than inferred. It is deliberately *not* fatal to the console:
    a credential mistake must not take out a tenant's whole UI, for the same reason ADR-0020 §7
    keeps a catalog outage from gating readiness. Everything else keeps working; the catalog
    features say why they cannot.
    """


class CatalogClient:
    def __init__(self, settings: Settings) -> None:
        self._configured = bool(settings.catalog_service_url and settings.catalog_api_token)
        #: The tenant this deployment IS, declared on every request (§7b). Empty on a
        #: provider-console BFF (`provider_oidc_enabled`), which legitimately holds the
        #: privileged credential and speaks for no single tenant — a declaration from it
        #: would itself be the misdelivery signal.
        self._declared_tenant_id = "" if settings.provider_oidc_enabled else settings.tenant_id
        headers = {}
        if settings.catalog_api_token:
            headers["Authorization"] = f"Bearer {settings.catalog_api_token}"
        if self._declared_tenant_id:
            # Set once on the long-lived client rather than per call, so there is no request
            # path that can omit it — the declaration being unskippable is the whole point.
            headers[TENANT_HEADER] = self._declared_tenant_id
        self._client = httpx.AsyncClient(
            base_url=settings.catalog_service_url or "http://catalog-not-configured.invalid",
            headers=headers,
            timeout=httpx.Timeout(10.0, read=30.0),
        )

    @staticmethod
    def _misdelivery_error_code(resp: httpx.Response) -> Optional[str]:
        """The catalog's §7b refusal codes, if this response is one."""
        if resp.status_code != 403:
            return None
        try:
            detail = resp.json().get("detail")
        except ValueError:
            return None
        if isinstance(detail, dict) and detail.get("error_code") in _MISDELIVERY_CODES:
            return str(detail["error_code"])
        return None

    async def request(self, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
        if not self._configured:
            raise CatalogUnavailable("CATALOG_SERVICE_URL / CATALOG_API_TOKEN not configured on this BFF")
        try:
            resp = await self._client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            raise CatalogUnavailable(str(exc)) from exc

        code = self._misdelivery_error_code(resp)
        if code:
            # Logged at ERROR every time rather than once: unlike the old client-side check
            # there is no cached verdict here, and a deployment holding the wrong credential
            # should keep saying so. The page comes from the catalog's own counter (§7b);
            # this line is what an operator reading the console's logs will find.
            logger.error(
                "catalog refused this BFF's credential (%s): this deployment declares tenant %r. "
                "The credential is valid and is installed in the wrong console (ADR-0020 §7b) — "
                "correct the provisioning, not the request. Catalog features are unavailable here "
                "until it is fixed.",
                code,
                self._declared_tenant_id,
            )
            raise CatalogMisconfigured(
                f"the catalog refused this deployment's credential for tenant " f"'{self._declared_tenant_id}' ({code})"
            )
        return resp

    async def aclose(self) -> None:
        await self._client.aclose()
