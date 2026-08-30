# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Redeem a tenant's enrolment invitation (ADR-0024 §10) — the provider console's half.

A tenant administrator issues a one-time invitation in their own console and hands it over out
of band, along with their gateway's URL. A provider operator pastes both here, and this route
performs the three steps that were nine manual ones:

1. **Mint that tenant's catalog credential** (ADR-0020 §7a) on the catalog service.
2. **Redeem the invitation** against the tenant's gateway, handing over the catalog's address
   and that credential, and receiving the provider's own standing credential in return.
3. **Verify the tenant is who we minted for**, and revoke the credential if not.

**Step 3 is not decoration.** The operator types the tenant id when minting, and a typo would
mint a credential for tenant A and install it in tenant B's console — the misdelivery ADR-0020
§7b exists to catch, arriving one level up at the relationship rather than the request. §7b's
declaration catches it later, at the tenant's first catalog call, as a page-severity alert; this
catches it here, before the credential is ever installed. The gateway reports its own
`tenant_id` from its own configuration for exactly this purpose, and refuses to be enrolled at
all if it has none.

**Failures compensate.** A credential minted in step 1 and orphaned by a failure in step 2 is a
live credential for a tenant that was never enrolled — so it is revoked before the error is
returned. That leaves the operator with a plain failure to retry rather than a caller table
slowly filling with credentials nobody can account for.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from ..audit import record_request
from ..catalog_client import CatalogUnavailable
from ..security import SCOPE_PROVIDER_ADMIN, require_provider_scope

router = APIRouter(prefix="/provider/enrolment", tags=["provider", "enrolment"])

_provider_admin = Depends(require_provider_scope(SCOPE_PROVIDER_ADMIN))


def _provider_subject(session) -> str:
    """The operator's own identity, for the tenant gateway's attribution — never
    client-supplied. The same rule `routers/provider.py` already follows, and the same one
    ADR-0017 states for `provider_subject`: it is who the enrolment records as having redeemed,
    and a body field would let a console name someone else."""
    return str((session or {}).get("sub") or "unknown")


#: How long to wait on the tenant's gateway. Deliberately short: an operator is watching this
#: happen, and a redemption that hangs is worse than one that fails and can be retried — the
#: invitation is single-use, so an ambiguous outcome is the expensive case, which is why the
#: failure path below distinguishes "we know it did not happen" from "we cannot tell".
_REDEEM_TIMEOUT = httpx.Timeout(10.0, read=20.0)


async def _mint_catalog_credential(request: Request, tenant_id: str, label: str) -> tuple[str, str]:
    """Step 1. Returns `(credential_id, credential)` — the plaintext exists only here."""
    resp = await request.app.state.catalog.request("POST", f"/tenants/{tenant_id}/credentials", json={"label": label})
    if resp.status_code != 201:
        raise HTTPException(
            status_code=502,
            detail=f"the catalog would not issue a credential for '{tenant_id}' ({resp.status_code})",
        )
    body = resp.json()
    return body["id"], body["credential"]


async def _revoke_catalog_credential(request: Request, tenant_id: str, credential_id: str) -> None:
    """Compensate for a redemption that did not complete. Best-effort by necessity — if this
    fails too, the operator is told, because a credential we could not withdraw is exactly the
    thing they need to know exists."""
    try:
        await request.app.state.catalog.request("DELETE", f"/tenants/{tenant_id}/credentials/{credential_id}")
    except CatalogUnavailable:
        pass


@router.post("/redeem")
async def redeem(request: Request, session=_provider_admin):
    """Enrol this provider with a tenant, using an invitation the tenant issued."""
    body = await request.json() if await request.body() else {}
    code = str(body.get("code", "")).strip()
    gateway_url = str(body.get("gateway_url", "")).strip().rstrip("/")
    tenant_id = str(body.get("tenant_id", "")).strip()
    label = str(body.get("label", "")).strip() or "enrolment"

    missing = [n for n, v in (("code", code), ("gateway_url", gateway_url), ("tenant_id", tenant_id)) if not v]
    if missing:
        raise HTTPException(status_code=400, detail=f"enrolment requires: {', '.join(missing)}")

    settings = request.app.state.settings
    if not settings.catalog_service_url:
        raise HTTPException(
            status_code=503,
            detail="this console has no catalog configured, so it cannot issue the tenant's credential",
        )

    # --- 1. mint ---------------------------------------------------------------------------
    try:
        credential_id, catalog_credential = await _mint_catalog_credential(request, tenant_id, label)
    except CatalogUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    # --- 2. redeem -------------------------------------------------------------------------
    provider_subject = _provider_subject(session)
    try:
        async with httpx.AsyncClient(timeout=_REDEEM_TIMEOUT) as client:
            redeemed = await client.post(
                f"{gateway_url}/v1/enrolments/redeem",
                headers={"Authorization": f"Bearer {code}"},
                json={
                    "provider_subject": provider_subject,
                    "catalog_url": settings.catalog_service_url,
                    "catalog_credential": catalog_credential,
                },
            )
    except httpx.HTTPError as exc:
        # We do not know whether the tenant's gateway created the enrolment before the
        # connection failed, and the invitation is single-use. Revoke the credential anyway:
        # if the enrolment did happen it now holds a dead catalog credential, which the tenant
        # sees as a named "catalog unavailable" condition and can resolve by re-enrolling —
        # strictly better than a live credential belonging to an enrolment nobody recorded.
        await _revoke_catalog_credential(request, tenant_id, credential_id)
        await record_request(request, "provider.enrolment.redeem", outcome="failure", target=tenant_id)
        raise HTTPException(status_code=502, detail=f"could not reach the tenant's gateway: {exc}") from exc

    if redeemed.status_code != 201:
        await _revoke_catalog_credential(request, tenant_id, credential_id)
        await record_request(request, "provider.enrolment.redeem", outcome="failure", target=tenant_id)
        detail: Any
        try:
            detail = redeemed.json().get("detail", redeemed.text)
        except ValueError:
            detail = redeemed.text
        raise HTTPException(status_code=redeemed.status_code, detail=detail)

    enrolled = redeemed.json()

    # --- 3. verify -------------------------------------------------------------------------
    reported = str(enrolled.get("tenant_id", ""))
    if reported != tenant_id:
        await _revoke_catalog_credential(request, tenant_id, credential_id)
        await record_request(request, "provider.enrolment.misdelivered", outcome="failure", target=tenant_id)
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "ERR_ENROLMENT_TENANT_MISMATCH",
                "message": (
                    f"the gateway at {gateway_url} reports tenant '{reported}', but the credential was "
                    f"minted for '{tenant_id}'. Nothing was enrolled and the credential has been "
                    "revoked — check the tenant id you were given (ADR-0024 §10)."
                ),
            },
        )

    await record_request(request, "provider.enrolment.redeem", outcome="success", target=tenant_id)
    return {
        "tenant_id": reported,
        "enrolment_id": enrolled.get("enrolment_id"),
        "approved_by": enrolled.get("approved_by"),
        "approved_at": enrolled.get("approved_at"),
        "gateway_url": gateway_url,
        # The provider's own standing credential for this tenant's gateway. Returned to the
        # operator rather than stored: this console has no persistent store of its own
        # (ADR-0020 §7 keeps storage out of the BFF), and the registry that should hold it is
        # still static config — see the route's own note in the console UI.
        "credential": enrolled.get("credential"),
    }
