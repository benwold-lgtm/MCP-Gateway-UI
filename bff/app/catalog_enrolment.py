# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Where a tenant console learns its catalog configuration (ADR-0024 §10).

§10's redemption hands the tenant's gateway two things it did not have: its provider's catalog
address, and **its own** credential for it (ADR-0020 §7a). The gateway stores them and offers
them back on one route, deliberately its own rather than a field on the enrolment listing — a
listing is a screen an admin leaves open, and a credential should be fetched by the component
that needs it, when it needs it.

This is that component. Until now the two values reached a tenant console only through
`CATALOG_SERVICE_URL` / `CATALOG_API_TOKEN`, which meant enrolling was necessary but not
sufficient: someone still had to copy a credential into a deployment and restart it. That
copy-and-restart is the last manual step in §10's flow, and this removes it for the same reason
ADR-0024 §11 removed the provider's.

**Provider consoles never use this.** A provider BFF holds the privileged catalog credential
from its own configuration and is not enrolled with anyone — it is the party others enrol
*with*. Installing this there would have it ask a tenant gateway for a credential it must never
hold, which is the misdelivery ADR-0020 §7b exists to catch.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

#: The gateway route §10 added for exactly this. Requires `support:administer`, which the BFF's
#: own service credential carries — this is the deployment asking for its own configuration,
#: not a human asking on someone's behalf, so there is no caller bearer to pass through.
CATALOG_CONFIGURATION_PATH = "/enrolments/catalog-configuration"


def gateway_resolver(gateway):
    """An async callable returning ``(catalog_url, catalog_credential)``, or None.

    None covers two different situations on purpose, because from here they call for the same
    behaviour — keep the catalog unconfigured and let the routes say so — and neither is an
    error this console can fix:

    * **404**: this tenant has no live enrolment. The ordinary state of a tenant that has not
      enrolled yet, and the reason the caller retries on a cooldown rather than giving up.
    * anything else: the gateway could not answer. Logged, not raised.
    """

    async def resolve() -> Optional[tuple[str, str]]:
        resp = await gateway.get(CATALOG_CONFIGURATION_PATH)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            logger.warning(
                "the gateway answered %s asking for this tenant's catalog configuration",
                resp.status_code,
            )
            return None
        body = resp.json()
        return str(body.get("catalog_url") or ""), str(body.get("catalog_credential") or "")

    return resolve
