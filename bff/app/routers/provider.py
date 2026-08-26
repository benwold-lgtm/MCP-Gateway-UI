# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Provider-plane routes: raising and polling a delegated support request (ADR-0017 §7,
slice 7). Replaces the act-on-tenant/elevated-grant routes removed at slice 6 — this is a
different mechanism, not a rebuild of the old one: the tenant's own gateway mints the
credential once a tenant admin approves, rather than this console asserting authority itself.

Every route here relays to the gateway using the BFF's *own* service credential
(`bearer=None`, the same `GatewayClient` default a password session falls back to), never
the operator's own token — the operator has no gateway credential of their own until a
request is approved, which is the entire reason to raise one. `provider_subject` names the
operator for the gateway's own attribution, filled in from the session's own subject and
never taken from the request body, mirroring `routers/catalog.py`'s `assigned_by` pattern.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..audit import OUTCOME_DENIED, OUTCOME_SUCCESS, outcome_for, record_request
from ..security import SCOPE_PROVIDER_ADMIN, _persist_session, current_session, require_provider_scope

router = APIRouter(prefix="/provider", tags=["provider"])

_provider_admin = Depends(require_provider_scope(SCOPE_PROVIDER_ADMIN))


class RaiseSupportRequestBody(BaseModel):
    requested_scopes: list[str] = []
    justification: str = ""
    public_key: str | None = None


def _provider_subject(session) -> str:
    """The operator's own identity, for the gateway's attribution — never client-supplied."""
    return str((session or {}).get("sub") or "unknown")


@router.post("/support-requests")
async def raise_support_request(body: RaiseSupportRequestBody, request: Request, session=_provider_admin) -> dict:
    subject = _provider_subject(session)
    payload = {
        "provider_subject": subject,
        "requested_scopes": body.requested_scopes,
        "justification": body.justification,
    }
    if body.public_key:
        payload["public_key"] = body.public_key
    gw = request.app.state.gateway
    resp = await gw.request("POST", "/support-requests", json=payload)
    await record_request(
        request,
        "provider.support_request.raise",
        outcome=outcome_for(resp.status_code),
        target=subject,
        status=resp.status_code,
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=_detail(resp))
    return resp.json()


@router.get("/support-requests/{request_id}")
async def poll_support_request(request_id: str, request: Request, session=_provider_admin) -> dict:
    """The raising session's own view. Not audited — a poll is a read, and the gateway's own
    approve/reject already recorded the decision that matters.

    Delivering an approved credential is not a bare passthrough: it must land on *this*
    session, not just in the response body, or nothing else on this session can use it."""
    subject = _provider_subject(session)
    gw = request.app.state.gateway
    resp = await gw.request("GET", f"/support-requests/{request_id}?provider_subject={quote(subject, safe='')}")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=_detail(resp))
    body = resp.json()
    if body.get("status") == "approved" and body.get("credential"):
        sess = await current_session(request)
        if isinstance(sess, dict):
            sess["support_grant"] = {"grant_id": body.get("grant_id"), "credential": body["credential"]}
            await _persist_session(request, sess)
    return body


@router.get("/support-grant")
async def current_support_grant(session=_provider_admin) -> dict:
    """Whether this session currently holds a delegated support grant, and its id — never
    the credential itself, which has no use to the browser and every use to an attacker."""
    grant = session.get("support_grant")
    if not isinstance(grant, dict) or not grant.get("credential"):
        return {"held": False}
    return {"held": True, "grant_id": grant.get("grant_id")}


@router.delete("/support-grant")
async def release_support_grant(request: Request, session=_provider_admin) -> dict:
    """End this session's own grant early. Idempotent, like the gateway's own revoke."""
    grant = session.get("support_grant")
    grant_id = grant.get("grant_id") if isinstance(grant, dict) else None
    if grant_id:
        gw = request.app.state.gateway
        await gw.request("DELETE", f"/support-grants/{grant_id}")
    sess = await current_session(request)
    if isinstance(sess, dict) and sess.pop("support_grant", None) is not None:
        await _persist_session(request, sess)
    await record_request(
        request,
        "provider.support_grant.release",
        outcome=OUTCOME_SUCCESS if grant_id else OUTCOME_DENIED,
        target=_provider_subject(session),
        grant_id=grant_id,
    )
    return {"released": grant_id}


def _detail(resp) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text
    return body.get("detail", resp.text) if isinstance(body, dict) else resp.text
