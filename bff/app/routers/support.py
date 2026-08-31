# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tenant-plane support-request management + notifications (ADR-0017 §7, slice 7).

The other half of `routers/provider.py`: a tenant admin's own inbox for requests a provider
operator raised, the standing-consent setting, and the durable notification list (ADR-0017
slice 5 on the gateway). Every route relays with the caller's *own* credential
(`relay_get`/`relay_request`, the same `upstream_bearer` every other tenant-plane route
uses) rather than the BFF's service token — deciding a support request is a tenant-admin act
that should be attributable to the human who made it, on the gateway's own audit chain, not
collapsed into a shared service identity.

Gated by `require_role("admin")`, matching backup/restore: this is fleet-governance
authority, not routine read access.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..audit import outcome_for, record_request
from ..relay import relay_get, relay_request
from ..security import require_role

router = APIRouter(prefix="/api", tags=["support"])

_admin = Depends(require_role("admin"))


def _passthrough(resp: httpx.Response) -> JSONResponse:
    try:
        body: Any = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    return JSONResponse(status_code=resp.status_code, content=body)


async def _audited(request: Request, resp: httpx.Response, action: str, target: str | None = None) -> JSONResponse:
    await record_request(request, action, outcome=outcome_for(resp.status_code), target=target, status=resp.status_code)
    return _passthrough(resp)


async def _optional_body(request: Request) -> Any:
    """An optional JSON body — `approve`'s `{"ttl_seconds": ...}` may be omitted entirely."""
    try:
        return await request.json()
    except Exception:
        return None


# --- support requests / grants ------------------------------------------------------------


@router.get("/support/requests", dependencies=[_admin])
async def list_support_requests(request: Request) -> JSONResponse:
    """The inbox: requests a provider operator has raised, awaiting a decision. A read,
    deliberately unaudited — same reasoning as every other list route in this BFF."""
    return _passthrough(await relay_get(request, "/support-requests"))


@router.post("/support/requests/{request_id}/approve", dependencies=[_admin])
async def approve_support_request(request_id: str, request: Request) -> JSONResponse:
    body = await _optional_body(request)
    resp = await relay_request(request, "POST", f"/support-requests/{request_id}/approve", json=body)
    return await _audited(request, resp, "tenant.support_request.approve", target=request_id)


@router.post("/support/requests/{request_id}/reject", dependencies=[_admin])
async def reject_support_request(request_id: str, request: Request) -> JSONResponse:
    resp = await relay_request(request, "POST", f"/support-requests/{request_id}/reject")
    return await _audited(request, resp, "tenant.support_request.reject", target=request_id)


@router.get("/support/grants", dependencies=[_admin])
async def list_support_grants(request: Request) -> JSONResponse:
    """ "Who can reach my stack right now" — a read, unaudited."""
    return _passthrough(await relay_get(request, "/support-grants"))


@router.delete("/support/grants/{grant_id}", dependencies=[_admin])
async def revoke_support_grant(grant_id: str, request: Request) -> JSONResponse:
    resp = await relay_request(request, "DELETE", f"/support-grants/{grant_id}")
    return await _audited(request, resp, "tenant.support_grant.revoke", target=grant_id)


# --- standing consent (§3) ----------------------------------------------------------------


@router.get("/support/standing-consent", dependencies=[_admin])
async def get_standing_consent(request: Request) -> JSONResponse:
    return _passthrough(await relay_get(request, "/support-requests/standing-consent"))


@router.post("/support/standing-consent", dependencies=[_admin])
async def enable_standing_consent(request: Request) -> JSONResponse:
    body = await request.json()
    resp = await relay_request(request, "POST", "/support-requests/standing-consent", json=body)
    return await _audited(request, resp, "tenant.support_standing_consent.enable")


@router.delete("/support/standing-consent", dependencies=[_admin])
async def disable_standing_consent(request: Request) -> JSONResponse:
    resp = await relay_request(request, "DELETE", "/support-requests/standing-consent")
    return await _audited(request, resp, "tenant.support_standing_consent.disable")


# --- notifications (ADR-0017 slice 5, gateway) --------------------------------------------


@router.get("/notifications", dependencies=[_admin])
async def list_notifications(request: Request) -> JSONResponse:
    """The durable tenant-facing signal surface — a break-glass activation, a frequently
    self-issued support grant. A read, unaudited."""
    return _passthrough(await relay_get(request, "/notifications"))


# --- enrolment: this tenant's relationship with its provider (ADR-0024 §10) ----------------
#
# Grouped here rather than in a router of their own because the gateway made the same call for
# the same reason: `api/enrolments.py` puts these behind `support:administer`, the scope that
# already governs the support-request inbox, on the grounds that "a tenant admin who can approve
# a support request but not see who is enrolled would be holding half a control". The console
# mirrors that grouping instead of inventing a second place for the same concept.
#
# `routers/enrolment.py` is the provider's half and is mounted only on a provider console. The
# two never coexist in one process — enrolling is the provider's act, and *being* enrolled is
# the tenant's.


@router.post("/enrolment/invitations", dependencies=[_admin])
async def create_enrolment_invitation(request: Request) -> JSONResponse:
    """Mint an invitation to hand to a provider out of band.

    Audited, and the plaintext code is in the gateway's response and nowhere else. This route
    passes it straight through without logging it: `record_request` receives the status and the
    label, never the body, so the code exists in the operator's browser and the response in
    flight, and in no durable record on this side.
    """
    body = await _optional_body(request) or {}
    resp = await relay_request(request, "POST", "/enrolment-invitations", json=body)
    return await _audited(
        request,
        resp,
        "tenant.enrolment_invitation.create",
        target=str(body.get("provider_label", "")) or None,
    )


@router.get("/enrolment/invitations", dependencies=[_admin])
async def list_enrolment_invitations(request: Request) -> JSONResponse:
    """Outstanding invitations — handed out and not yet redeemed. A read, unaudited."""
    return _passthrough(await relay_get(request, "/enrolment-invitations"))


@router.delete("/enrolment/invitations/{code_hash}", dependencies=[_admin])
async def revoke_enrolment_invitation(code_hash: str, request: Request) -> JSONResponse:
    """Withdraw an invitation before it is redeemed — a handover that went to the wrong place
    should be endable without waiting out its TTL."""
    resp = await relay_request(request, "DELETE", f"/enrolment-invitations/{code_hash}")
    return await _audited(request, resp, "tenant.enrolment_invitation.revoke", target=code_hash)


@router.get("/enrolment/enrolments", dependencies=[_admin])
async def list_enrolments(request: Request) -> JSONResponse:
    """Who is enrolled, who approved it, and when it was last used.

    A read, unaudited like every other listing here. `last_used_at` is the reason this screen
    exists: §10 chose revocation over expiry, so a relationship that has gone dormant is only
    discoverable by looking at it — and a console that never showed the field would leave that
    decision's one safeguard unexercised.
    """
    return _passthrough(await relay_get(request, "/enrolments"))


@router.delete("/enrolment/enrolments/{enrolment_id}", dependencies=[_admin])
async def revoke_enrolment(enrolment_id: str, request: Request) -> JSONResponse:
    """End the relationship. Idempotent on the gateway (ADR-0017 §8's reasoning): a tenant
    admin ending a supplier relationship is very often doing it *because* something is wrong
    right now, and a button that errors on the second click fails when it matters."""
    resp = await relay_request(request, "DELETE", f"/enrolments/{enrolment_id}")
    return await _audited(request, resp, "tenant.enrolment.revoke", target=enrolment_id)


@router.get("/enrolment/this-tenant", dependencies=[_admin])
async def this_tenant(request: Request) -> JSONResponse:
    """What a tenant admin has to hand their provider, alongside an invitation code.

    The three things §10's handshake needs are the code, this gateway's externally reachable
    address, and this tenant's id — and until now the console showed only the first. The other
    two lived in a Kubernetes ConfigMap and a lab notebook, so "invite a provider" produced a
    credential and left the operator to source two more values from outside the product.

    Deliberately reports what is MISSING rather than substituting anything. `gateway_url` is
    the in-cluster service address and would be actively wrong to show here; an unset
    `PUBLIC_GATEWAY_URL` therefore returns empty, and the console names the setting instead of
    printing something that would fail at redemption.

    Admin-only, matching the rest of this module: it is one screen with the invitation form
    and the same `support:administer` authority covers both. Neither value is a secret — the
    gate is consistency, not confidentiality.
    """
    settings = request.app.state.settings
    return JSONResponse(
        {
            "tenant_id": settings.tenant_id or "",
            "public_gateway_url": settings.public_gateway_url or "",
        }
    )
