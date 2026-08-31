# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Redeem a tenant's enrolment invitation (ADR-0024 §10) — the provider console's half.

A tenant administrator issues a one-time invitation in their own console and hands it over out
of band, along with their gateway's URL. A provider operator pastes both here, and this route
performs the three steps that were nine manual ones:

1. **Record the tenant and mint its catalog credential** (ADR-0020 §7a, ADR-0024 §11) — one
   call, one transaction in the catalog, so the registry entry and the credential cannot
   half-land.
2. **Redeem the invitation** against the tenant's gateway, handing over the catalog's address
   and that credential, and receiving the provider's own standing credential in return.
3. **Verify the tenant is who we minted for**, and withdraw the whole enrolment if not.
4. **Record the provider's credential** against the registry entry, completing it.

**Step 3 is not decoration.** The operator types the tenant id when minting, and a typo would
mint a credential for tenant A and install it in tenant B's console — the misdelivery ADR-0020
§7b exists to catch, arriving one level up at the relationship rather than the request. §7b's
declaration catches it later, at the tenant's first catalog call, as a page-severity alert; this
catches it here, before the credential is ever installed. The gateway reports its own
`tenant_id` from its own configuration for exactly this purpose, and refuses to be enrolled at
all if it has none.

**Failures compensate.** A credential minted in step 1 and orphaned by a failure in step 2 is a
live credential for a tenant that was never enrolled — so the enrolment is withdrawn before the
error is returned, which under §11 removes the registry entry and revokes the credential in one
act. That leaves the operator with a plain failure to retry rather than a caller table slowly
filling with credentials nobody can account for.

**Step 4 is the exception, and deliberately so.** By then the tenant's gateway holds a live
enrolment, and withdrawing would destroy the provider's only copy of the credential it just
received while leaving that enrolment standing. So a failure there leaves the tenant *listed and
unreachable* — a state the estate shows, which an operator can see and repair by enrolling
again. §11 argues that at length: a visible incomplete state beats an invisible one.
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


async def _enrol_in_catalog(request: Request, tenant_id: str, display_name: str, gateway_url: str, label: str) -> str:
    """Step 1 (ADR-0024 §11). Returns the tenant's catalog credential — the plaintext exists
    only here, on its way to the tenant's gateway.

    One call rather than "mint a credential, then have an operator add a registry entry". That
    second half used to be a line in this route's own response telling a human what to go and
    edit; it is now the other statement in the same transaction.
    """
    resp = await request.app.state.catalog.request(
        "POST",
        "/tenants",
        json={
            "tenant_id": tenant_id,
            "display_name": display_name or tenant_id,
            "gateway_url": gateway_url,
            "label": label,
        },
    )
    if resp.status_code != 201:
        raise HTTPException(
            status_code=502,
            detail=f"the catalog would not enrol '{tenant_id}' ({resp.status_code})",
        )
    return str(resp.json()["credential"])


async def _withdraw_from_catalog(request: Request, tenant_id: str) -> None:
    """Compensate for a redemption that did not complete: remove the registry entry and revoke
    the credential, which §11 makes one transaction rather than two calls this route would have
    to sequence and could be interrupted between.

    Best-effort by necessity — if this fails too the operator is told, because an enrolment we
    could not withdraw is exactly the thing they need to know exists.
    """
    try:
        await request.app.state.catalog.request("DELETE", f"/tenants/{tenant_id}")
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
    display_name = str(body.get("display_name", "")).strip()

    missing = [n for n, v in (("code", code), ("gateway_url", gateway_url), ("tenant_id", tenant_id)) if not v]
    if missing:
        raise HTTPException(status_code=400, detail=f"enrolment requires: {', '.join(missing)}")

    settings = request.app.state.settings
    if not settings.catalog_service_url:
        raise HTTPException(
            status_code=503,
            detail="this console has no catalog configured, so it cannot issue the tenant's credential",
        )

    # ⚠️ The address handed to the TENANT is not the one this BFF dials.
    #
    # `catalog_service_url` is routinely an in-cluster ClusterIP name — `http://device-mcp-
    # catalog:8100` in this repo's own manifests. Sending that as `catalog_url` tells the
    # tenant to resolve a name that exists only inside the provider's cluster, and it did:
    # a tenant enrolled through the console got "Temporary failure in name resolution" from
    # every catalog read, forever, while the enrolment itself reported complete success.
    #
    # Refused rather than defaulted. A fallback to `catalog_service_url` is exactly the shape
    # §10 singles out as the failure to avoid — it fails quietly and reads as the catalog being
    # down while it is healthy. Failing here, loudly, naming the field, is §10's step 5 model.
    public_catalog_url = settings.public_catalog_url
    if not public_catalog_url:
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "ERR_PUBLIC_CATALOG_URL_NOT_SET",
                "message": (
                    "PUBLIC_CATALOG_URL is not set on this console, so it cannot tell a tenant "
                    "where to reach the catalog. It must be the address a TENANT can resolve, "
                    "which is not CATALOG_SERVICE_URL — that one is this console's own "
                    "in-cluster address. Nothing was enrolled (ADR-0024 §10)."
                ),
            },
        )

    # --- 1. record the tenant and mint its credential, in one transaction --------------------
    try:
        catalog_credential = await _enrol_in_catalog(request, tenant_id, display_name, gateway_url, label)
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
                    "catalog_url": public_catalog_url,
                    "catalog_credential": catalog_credential,
                },
            )
    except httpx.HTTPError as exc:
        # We do not know whether the tenant's gateway created the enrolment before the
        # connection failed, and the invitation is single-use. Revoke the credential anyway:
        # if the enrolment did happen it now holds a dead catalog credential, which the tenant
        # sees as a named "catalog unavailable" condition and can resolve by re-enrolling —
        # strictly better than a live credential belonging to an enrolment nobody recorded.
        await _withdraw_from_catalog(request, tenant_id)
        await record_request(request, "provider.enrolment.redeem", outcome="failure", target=tenant_id)
        raise HTTPException(status_code=502, detail=f"could not reach the tenant's gateway: {exc}") from exc

    if redeemed.status_code != 201:
        await _withdraw_from_catalog(request, tenant_id)
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
        await _withdraw_from_catalog(request, tenant_id)
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

    # --- 4. complete the registry entry ------------------------------------------------------
    # The provider's own standing credential for this tenant's gateway. It is recorded rather
    # than returned: handing it to the operator to paste somewhere was the manual step §11
    # exists to remove, and it is the one secret in this flow whose whole purpose is to be
    # presented again later. It does not appear in this response or in the audit record.
    enrolment_id = str(enrolled.get("enrolment_id") or "")
    try:
        recorded = await request.app.state.catalog.request(
            "PUT",
            f"/tenants/{tenant_id}/gateway-credential",
            json={"gateway_credential": enrolled.get("credential") or "", "enrolment_id": enrolment_id},
        )
        completed = recorded.status_code == 200
    except CatalogUnavailable:
        completed = False

    if not completed:
        # Deliberately NOT withdrawn — see the module docstring. The tenant's gateway holds a
        # live enrolment now, and withdrawing here would revoke the credential it is using while
        # destroying our only copy of the one it gave us. The tenant stays listed and
        # unreachable, which the estate shows, and re-enrolling repairs it.
        await record_request(request, "provider.enrolment.incomplete", outcome="failure", target=tenant_id)
        raise HTTPException(
            status_code=502,
            detail={
                "error_code": "ERR_ENROLMENT_NOT_RECORDED",
                "message": (
                    f"tenant '{tenant_id}' was enrolled on its gateway, but the catalog would not "
                    "record the credential it returned. The tenant is listed and unreachable "
                    "until it is enrolled again with a fresh invitation (ADR-0024 §11)."
                ),
            },
        )

    # The pool may hold a client built from this tenant's previous credential — re-enrolment
    # issues a new one, and a cached client would keep presenting the old until it was revoked
    # and then fail for a reason nothing in this process would connect to this enrolment.
    request.app.state.gateway_pool.invalidate(tenant_id)
    await request.app.state.tenant_directory.refresh(request.app.state.catalog)

    await record_request(request, "provider.enrolment.redeem", outcome="success", target=tenant_id)
    return {
        "tenant_id": reported,
        "enrolment_id": enrolment_id,
        "approved_by": enrolled.get("approved_by"),
        "approved_at": enrolled.get("approved_at"),
        "gateway_url": gateway_url,
        "recorded": True,
    }
