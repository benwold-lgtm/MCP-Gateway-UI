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

**Where the credential comes from changed again in ADR-0024 §10.** Env is still read first and
still wins when set — an operator who configured `CATALOG_API_TOKEN` deliberately should not
have it silently overridden by a value fetched from somewhere else, and every existing
deployment behaves exactly as it did. But a tenant that has *enrolled* now has its catalog
address and credential held by its own gateway, minted during the handshake, and this client
will ask for them when env gave it nothing. That is what makes enrolling sufficient on its own:
the tenant gains catalog access without a redeploy, which was §10's whole point.

Resolution is **lazy and repeatable**, not a startup step. A console whose gateway is briefly
down at boot must not be permanently catalog-less, and a tenant that enrols an hour after its
console started must not need a restart to notice. It is also retried once on a 401, which is
what a revoked-and-re-enrolled credential looks like from here.

ADR-0020 §7: the catalog's unavailability must be a **named condition**, never inferred from
an empty list — a provider console showing no device types because the catalog is down must
not look like a provider who has curated none. `CatalogUnavailable` is what lets a route tell
the two apart; see `routers/catalog.py`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Optional

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

#: How long to wait before asking the gateway again after a resolution that produced nothing.
#: Long enough that a console whose tenant has not enrolled is not asking on every page load,
#: short enough that enrolling is felt as "it works now" rather than "restart the console".
#: A *successful* resolution is not re-attempted at all until a 401 says the credential died.
RESOLVE_COOLDOWN_SECONDS = 30.0

#: Returns ``(catalog_url, catalog_credential)``, or None when there is nothing to learn.
CatalogResolver = Callable[[], Awaitable[Optional[tuple[str, str]]]]


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
    def __init__(self, settings: Settings, resolver: Optional[CatalogResolver] = None) -> None:
        self._configured = bool(settings.catalog_service_url and settings.catalog_api_token)
        #: Where to learn the address and credential when env gave none (ADR-0024 §10). Never
        #: consulted while `_configured` — explicit configuration wins, so installing a
        #: resolver cannot change how an already-working deployment behaves.
        self._resolver = resolver
        self._resolve_lock = asyncio.Lock()
        self._resolve_attempted_at = 0.0
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

    @property
    def configured(self) -> bool:
        """Whether this BFF has a catalog to talk to at all.

        Distinct from "the catalog is down": a deployment with no catalog configured is a
        supported arrangement, not a degraded one, and a caller that conflated them would show
        every such deployment a permanent outage warning.
        """
        return self._configured

    async def _resolve(self, *, force: bool = False) -> bool:
        """Ask the resolver for this deployment's catalog address and credential (§10).

        Returns whether the client is configured afterwards. Serialised by a lock so a burst of
        concurrent requests on a cold console produces one gateway call, not one per request —
        and rate-limited by a cooldown so a tenant that has not enrolled is not asking on every
        page load. `force` is the 401 path: the credential we hold has stopped working, which is
        what a revoked-and-re-enrolled relationship looks like from here, so the cooldown is
        bypassed once rather than making the console wait it out.
        """
        if self._resolver is None:
            return self._configured
        async with self._resolve_lock:
            # Re-checked inside the lock: while this coroutine waited, another may have already
            # done the work, and the point of the lock is that only one call goes out.
            if self._configured and not force:
                return True
            now = time.monotonic()
            if not force and now - self._resolve_attempted_at < RESOLVE_COOLDOWN_SECONDS:
                return self._configured
            self._resolve_attempted_at = now
            try:
                found = await self._resolver()
            except Exception as exc:
                # Never fatal. A gateway that cannot answer leaves the catalog unconfigured,
                # which every route already renders as a named condition — the same posture
                # ADR-0020 §7 takes towards a catalog outage, applied one step earlier.
                logger.warning("could not learn this tenant's catalog configuration: %s", exc)
                return self._configured
            if not found:
                return self._configured
            url, credential = found
            if not url or not credential:
                return self._configured
            self._adopt(url, credential)
            logger.info("learned this tenant's catalog configuration from its enrolment (ADR-0024 §10)")
            return True

    def _adopt(self, url: str, credential: str) -> None:
        """Point the live client at a newly learned address and credential.

        Mutates the existing `AsyncClient` rather than replacing it: a replacement would orphan
        the connection pool of any request in flight. The tenant declaration is deliberately
        left alone — it comes from this deployment's own identity (§7b), never from anything
        handed to it, and a credential arriving with the power to change what tenant this
        console claims to be would defeat the check.
        """
        self._client.base_url = httpx.URL(url)
        self._client.headers["Authorization"] = f"Bearer {credential}"
        self._configured = True

    async def request(self, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
        if not self._configured:
            await self._resolve()
        if not self._configured:
            raise CatalogUnavailable(
                "this BFF has no catalog: CATALOG_SERVICE_URL / CATALOG_API_TOKEN are unset and "
                "this tenant has no enrolment to learn them from (ADR-0024 §10)"
            )
        try:
            resp = await self._client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            raise CatalogUnavailable(str(exc)) from exc

        if resp.status_code == 401 and self._resolver is not None:
            # The credential we hold has stopped being accepted. Re-enrolling is the ordinary
            # way a tenant repairs this, and it mints a NEW credential — so ask once, and retry
            # only if we actually learned something different. Without this the console would
            # keep presenting a dead credential until someone restarted it.
            before = self._client.headers.get("Authorization")
            if await self._resolve(force=True) and self._client.headers.get("Authorization") != before:
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
