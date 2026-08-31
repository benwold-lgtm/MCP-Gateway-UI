# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Which tenants this provider serves (ADR-0024 §11) — config underneath, the catalog on top.

`tenant_registry.py` reads `PROVIDER_TENANT_REGISTRY`, which §11 closed as the *sole* source:
enrolment and revocation are routine and in-band, and a registry that can only change by a
config edit and a rollout makes §10's revocation model unbuildable as anything but a manual
out-of-band task. The catalog's `tenants` table is now the live source.

**Config is not removed, it is the floor.** Two reasons, and only the second is about outages:

* a provider that has not adopted enrolment keeps working exactly as before;
* when the catalog is unreachable, the console still knows who its tenants are. An estate that
  vanished during a catalog outage would take the provider's ability to *reach* its tenants with
  it, at precisely the moment they are most likely to need support.

So a refresh that fails leaves the last known estate standing and says so; it never empties it.
A refresh that *succeeds* replaces the enrolled set wholesale, because a tenant the catalog no
longer lists has been withdrawn, and withdrawal has to take effect without a redeploy — which
was the whole argument for moving off config.
"""

from __future__ import annotations

import logging
from typing import Optional

from .catalog_client import CatalogUnavailable
from .tenant_registry import TenantEntry

logger = logging.getLogger(__name__)


class TenantDirectory:
    def __init__(self, configured: dict[str, TenantEntry]) -> None:
        self._configured = dict(configured)
        self._enrolled: dict[str, TenantEntry] = {}
        self._last_refresh_failed = False

    # --- reads -----------------------------------------------------------------------------

    def entries(self) -> dict[str, TenantEntry]:
        """The estate, catalog entries taking precedence over same-id config entries.

        Catalog wins on a collision because it is the one that can have changed since boot: a
        tenant present in both is one whose config entry predates its enrolment, and preferring
        the stale copy would silently route to a gateway URL the tenant has since moved from.
        """
        merged = dict(self._configured)
        merged.update(self._enrolled)
        return merged

    def get(self, tenant_id: str) -> TenantEntry:
        """Raises ``KeyError`` for a tenant this directory doesn't name — callers translate it
        to a 404, never a 500: an operator naming an unknown tenant is a client error."""
        return self.entries()[tenant_id]

    def __contains__(self, tenant_id: object) -> bool:
        return tenant_id in self.entries()

    @property
    def stale(self) -> bool:
        """True when the last refresh could not reach the catalog, so the estate being served is
        the last known one rather than the current one. Exposed so a console can say which it is
        showing — the difference between "this provider has three tenants" and "we could not ask"
        is exactly the kind an operator during an incident must not have to guess at."""
        return self._last_refresh_failed

    # --- refresh ---------------------------------------------------------------------------

    async def refresh(self, catalog) -> bool:
        """Re-read the enrolled estate from the catalog. Best-effort by design; returns whether
        it succeeded so a caller can report staleness rather than silently serving old data."""
        if not getattr(catalog, "configured", True):
            # Not an outage. A console with no catalog configured serves its config registry and
            # is entirely correct in doing so — reporting that as stale would show a permanent
            # warning to every deployment that has not adopted enrolment, which is precisely the
            # audience §11 promised to leave alone.
            self._last_refresh_failed = False
            return True
        try:
            resp = await catalog.request("GET", "/tenants")
        except CatalogUnavailable as exc:
            return self._failed(f"catalog unavailable: {exc}")
        if resp.status_code != 200:
            return self._failed(f"the catalog answered {resp.status_code} listing tenants")

        try:
            rows = resp.json()["tenants"]
        except (ValueError, KeyError, TypeError) as exc:
            # A 200 whose body is not what we expect is a *failure*, not an empty estate.
            # Treating it as empty would drop every enrolled tenant on a malformed response —
            # the "a default reads as a measurement" shape this project has paid for before.
            return self._failed(f"the catalog's tenant listing was unreadable: {exc}")

        self._enrolled = {
            str(row["tenant_id"]): TenantEntry(
                tenant_id=str(row["tenant_id"]),
                display_name=str(row.get("display_name") or row["tenant_id"]),
                gateway_url=str(row.get("gateway_url") or ""),
                from_catalog=True,
            )
            for row in rows
            if row.get("tenant_id")
        }
        self._last_refresh_failed = False
        return True

    def _failed(self, why: str) -> bool:
        if not self._last_refresh_failed:
            # Logged once per transition rather than on every list view: a console polling a
            # down catalog would otherwise bury every other line in the log.
            logger.warning("tenant directory: serving the last known estate — %s", why)
        self._last_refresh_failed = True
        return False

    # --- the credential, fetched only when a tenant is actually contacted -------------------

    async def gateway_credential(self, catalog, tenant_id: str) -> Optional[str]:
        """The provider's own credential for one tenant's gateway.

        Not part of `entries()` and not cached here. The catalog deliberately offers this as its
        own route rather than a field on the listing, for the reason its repo states: a listing
        is a screen left open, and a credential should be fetched by the component that needs
        it, when it needs it. Mirroring that here is what keeps the property true end to end.

        Returns None when the catalog cannot answer, which callers must treat as "unreachable",
        never as "no credential" — an empty credential is a legitimate configuration for a lab
        gateway with no auth, and conflating the two would turn an outage into a silent 401.
        """
        try:
            resp = await catalog.request("GET", f"/tenants/{tenant_id}/gateway-credential")
        except CatalogUnavailable:
            return None
        if resp.status_code != 200:
            return None
        try:
            return str(resp.json().get("gateway_credential", ""))
        except ValueError:
            return None
