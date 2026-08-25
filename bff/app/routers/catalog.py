# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Provider-plane device-type curation and assignment (ADR-0020 §1/§2, slice 3).

Relays to the standalone catalog service (`device_mcp_catalog/`) — this router holds no
storage of its own, per ADR-0020 §7: the catalog is not the BFF's responsibility. Every
route here is provider-plane by construction (`require_provider_scope`), mirroring
`provider.py`'s act-on-tenant routes — a tenant session must not reach curation or
assignment however its IdP names its groups.

The claim flow (slice 4) is deliberately **not** here: claiming is a tenant-plane act (ADR-0020
§2 — "neither can do the other's half"), so it belongs on the tenant-facing router in `api.py`,
not this provider-only one.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..audit import outcome_for, record_request
from ..catalog_client import CatalogUnavailable
from ..security import SCOPE_PROVIDER_ADMIN, require_provider_scope

router = APIRouter(prefix="/provider/catalog", tags=["provider", "catalog"])

_provider_admin = Depends(require_provider_scope(SCOPE_PROVIDER_ADMIN))


def _passthrough(resp: httpx.Response) -> JSONResponse:
    try:
        body: Any = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    return JSONResponse(status_code=resp.status_code, content=body)


async def _relay(request: Request, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
    try:
        return await request.app.state.catalog.request(method, path, json=json)
    except CatalogUnavailable as exc:
        # Named condition (ADR-0020 §7), not a 500: the provider console must be able to
        # tell "the catalog is down" apart from "nothing is curated yet".
        raise HTTPException(status_code=503, detail=f"catalog service unavailable: {exc}")


async def _relay_audited(
    request: Request, method: str, path: str, action: str, *, json: Optional[Any] = None
) -> JSONResponse:
    resp = await _relay(request, method, path, json=json)
    await record_request(request, action, outcome=outcome_for(resp.status_code), target=path, status=resp.status_code)
    return _passthrough(resp)


# --- device-type curation --------------------------------------------------------------


@router.post("/device-types")
async def create_device_type(request: Request, session=_provider_admin) -> JSONResponse:
    body = await request.json()
    return await _relay_audited(request, "POST", "/device-types", "provider.catalog.device_type.create", json=body)


@router.post("/device-types/{type_id}/versions")
async def add_device_type_version(type_id: str, request: Request, session=_provider_admin) -> JSONResponse:
    body = await request.json()
    return await _relay_audited(
        request, "POST", f"/device-types/{type_id}/versions", "provider.catalog.device_type.add_version", json=body
    )


@router.get("/device-types")
async def list_device_types(request: Request, session=_provider_admin) -> JSONResponse:
    # Read, deliberately unaudited — same reasoning as provider.py's `tenants`/`current`:
    # a provider looking at the catalog has not changed anything in it.
    resp = await _relay(request, "GET", "/device-types")
    return _passthrough(resp)


@router.get("/device-types/{type_id}")
async def get_device_type(type_id: str, request: Request, session=_provider_admin) -> JSONResponse:
    resp = await _relay(request, "GET", f"/device-types/{type_id}")
    return _passthrough(resp)


# --- assignment -------------------------------------------------------------------------


@router.post("/device-types/{type_id}/assign")
async def assign_device_type(type_id: str, request: Request, session=_provider_admin) -> JSONResponse:
    body = await request.json()
    tenant_id = body.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="'tenant_id' is required")
    # `assigned_by` is never taken from the browser — a client asserting its own audit
    # attribution is exactly the thing a server-side actor field exists to prevent. The
    # session's own subject is the one this BFF can vouch for.
    payload = {"tenant_id": tenant_id, "assigned_by": str(session.get("sub") or "unknown")}
    return await _relay_audited(
        request, "POST", f"/device-types/{type_id}/assign", "provider.catalog.assign", json=payload
    )


@router.delete("/device-types/{type_id}/assign/{tenant_id}")
async def revoke_assignment(type_id: str, tenant_id: str, request: Request, session=_provider_admin) -> JSONResponse:
    resp = await _relay(request, "DELETE", f"/device-types/{type_id}/assign/{tenant_id}")
    await record_request(
        request,
        "provider.catalog.revoke",
        outcome=outcome_for(resp.status_code),
        target=f"{type_id}:{tenant_id}",
        status=resp.status_code,
    )
    if resp.status_code == 204:
        return JSONResponse(status_code=204, content=None)
    return _passthrough(resp)


@router.get("/tenants/{tenant_id}/assignments")
async def tenant_assignments(tenant_id: str, request: Request, session=_provider_admin) -> JSONResponse:
    """What a tenant is currently offered — read, unaudited, same reasoning as the list
    route above. Used by the provider console to render assign/revoke state for a tenant."""
    resp = await _relay(request, "GET", f"/tenants/{tenant_id}/assignments")
    return _passthrough(resp)
