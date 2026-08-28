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
*tenant's* token is refused there. The one case it cannot see is a tenant BFF configured with
the **provider's** token — that request authenticates correctly, as the provider, with every
tenant's data in reach. `request()` closes it here, by asking `/whoami` once and refusing to
use a credential that does not answer with this deployment's own tenant.

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


class CatalogUnavailable(Exception):
    """The catalog service is unreachable, or this BFF has no token configured for it."""


class CatalogMisconfigured(CatalogUnavailable):
    """This BFF's catalog credential is not the one this deployment should hold (§7a).

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
        #: The tenant this deployment IS, and only when this deployment is a tenant plane.
        #: A provider-console BFF (`provider_oidc_enabled`) legitimately holds the privileged
        #: credential and speaks for no single tenant, so it is not checked against one — the
        #: check is for the deployment that must NOT hold that credential.
        self._expect_tenant_id = "" if settings.provider_oidc_enabled else settings.tenant_id
        #: None = not yet asked. Kept as tri-state on purpose: a failed check must be
        #: retried (the catalog may simply have been down), while a check that came back
        #: *wrong* is a configuration fact that will not change until someone redeploys.
        self._identity_ok: Optional[bool] = None
        headers = {}
        if settings.catalog_api_token:
            headers["Authorization"] = f"Bearer {settings.catalog_api_token}"
        self._client = httpx.AsyncClient(
            base_url=settings.catalog_service_url or "http://catalog-not-configured.invalid",
            headers=headers,
            timeout=httpx.Timeout(10.0, read=30.0),
        )

    async def _check_identity(self) -> None:
        """Confirm once that this deployment's credential speaks for this deployment's tenant.

        Lazy rather than done at startup, deliberately: a startup probe would either make the
        console's boot depend on the catalog being up — which ADR-0020 §7 refuses — or pass
        silently whenever the catalog happened to be slow, which is a check that reports
        success for the wrong reason.
        """
        if self._identity_ok is not None:
            if self._identity_ok:
                return
            raise CatalogMisconfigured(
                "this BFF's catalog credential does not belong to tenant " f"'{self._expect_tenant_id}' (ADR-0020 §7a)"
            )
        try:
            resp = await self._client.get("/whoami")
        except httpx.HTTPError as exc:
            # Unreachable, not wrong. Leave the check unmade so it runs again later.
            raise CatalogUnavailable(str(exc)) from exc
        if resp.status_code != 200:
            raise CatalogUnavailable(f"catalog rejected this BFF's credential ({resp.status_code})")

        body = resp.json()
        if body.get("kind") == "tenant" and body.get("tenant_id") == self._expect_tenant_id:
            self._identity_ok = True
            return

        self._identity_ok = False
        logger.error(
            "catalog credential mismatch: this BFF serves tenant %r but its catalog token "
            "authenticates as %r/%r. Refusing to use it — a tenant BFF holding the provider's "
            "credential can read and write every tenant's catalog data (ADR-0020 §7a). "
            "Disabling catalog features until this deployment is corrected.",
            self._expect_tenant_id,
            body.get("kind"),
            body.get("tenant_id"),
        )
        raise CatalogMisconfigured(
            f"this BFF's catalog credential does not belong to tenant '{self._expect_tenant_id}' (ADR-0020 §7a)"
        )

    async def request(self, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
        if not self._configured:
            raise CatalogUnavailable("CATALOG_SERVICE_URL / CATALOG_API_TOKEN not configured on this BFF")
        # Skipped entirely on a provider console and on a tenant stack with no TENANT_ID
        # configured — the latter cannot state which tenant it is, so there is nothing to
        # check the credential against and inventing an expectation would be worse than none.
        if self._expect_tenant_id:
            await self._check_identity()
        try:
            return await self._client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            raise CatalogUnavailable(str(exc)) from exc

    async def aclose(self) -> None:
        await self._client.aclose()
