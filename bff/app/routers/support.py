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
