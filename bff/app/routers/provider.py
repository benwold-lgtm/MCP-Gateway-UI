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

Since ADR-0021 (scoped), "the gateway" is no longer singular: a provider console can reach
more than one tenant, so every route names a `tenant_id` and resolves its gateway from
`app.state.gateway_pool` (see `gateway_pool.py`) rather than a single fixed client.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..audit import OUTCOME_DENIED, OUTCOME_SUCCESS, outcome_for, record_request
from ..gateway_pool import TenantUnreachable
from ..security import (
    SCOPE_PROVIDER_ADMIN,
    SCOPE_PROVIDER_MONITOR,
    _persist_session,
    current_session,
    require_provider_scope,
    requestable_scopes_for,
)

router = APIRouter(prefix="/provider", tags=["provider"])

# Every route in this module is monitor-or-admin since §7b. The admin-only dependency that
# used to sit here is gone rather than left unused — catalog.py keeps its own, and that is
# the one provider surface still genuinely admin-only.
# Either scope may read the tenant directory: it's pure navigation (which tenants exist,
# where to raise a request), not a grant of access to any of them — provider:monitor's
# "aggregate estate health" is exactly this, and an admin needs the same list before they
# can raise a request in the first place.
#
# ADR-0017 §7b: the same dependency now carries the whole support-request loop. Asking is
# not itself an authority — the tenant decides — so gating the *ask* on provider:admin only
# meant a read-only operator had to find an admin to ask on their behalf, which loses the
# attribution §7 is built to preserve. What a monitor may ask *for* is narrowed instead, by
# `requestable_scopes_for` on the raise route.
#
# Raise, poll, hold and release move together on purpose: a session that may raise but may
# not poll can ask and never learn the answer, and one that may not release cannot hand
# back what it holds. Splitting them would produce a role that is worse than either.
_provider_read = Depends(require_provider_scope(SCOPE_PROVIDER_MONITOR, SCOPE_PROVIDER_ADMIN))


@router.get("/tenants")
async def list_tenants(request: Request, session=_provider_read) -> dict:
    """The provider console's own directory of known tenants (ADR-0021, scoped) — where to
    raise a support request, not whether one will be approved. A read, so not audited (the
    same convention `poll_support_request` and `routers/catalog.py`'s list routes follow).

    `gateway_url` is deliberately never returned: the frontend only ever needs a `tenant_id`
    to pass back into the raise/poll routes, and the registry's internal topology is not
    something the browser needs to see.

    Refreshed from the catalog on each call (ADR-0024 §11), because an estate that only changed
    at boot is the config-shaped registry §11 replaced — a tenant enrolled or withdrawn a minute
    ago has to be right here. `stale` reports a refresh that could not reach the catalog, so the
    console can say it is showing the last known estate rather than presenting it as current.
    """
    directory = request.app.state.tenant_directory
    await directory.refresh(request.app.state.catalog)
    return {
        "tenants": [
            {"tenant_id": entry.tenant_id, "display_name": entry.display_name}
            for entry in sorted(directory.entries().values(), key=lambda entry: entry.display_name)
        ],
        "stale": directory.stale,
    }


class RaiseSupportRequestBody(BaseModel):
    tenant_id: str
    requested_scopes: list[str] = []
    justification: str = ""
    public_key: str | None = None


def _provider_subject(session) -> str:
    """The operator's own identity, for the gateway's attribution — never client-supplied."""
    return str((session or {}).get("sub") or "unknown")


async def _gateway_for(request: Request, tenant_id: str):
    """The pool resolves an unknown tenant_id to ``KeyError`` — translated to a 404 here,
    never a 500: the operator named a tenant this registry doesn't know (a stale bookmark,
    a typo), which is a client error, not a server fault.

    ``TenantUnreachable`` is the other half of that distinction (ADR-0024 §11): the tenant is
    known and enrolled, and its credential could not be fetched from the catalog. 503, because
    "we could not ask" is an outage and "there is no such tenant" is a typo, and an operator
    working an incident should not have to tell them apart from a single status code.
    """
    try:
        return await request.app.state.gateway_pool.get(tenant_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown tenant: {tenant_id!r}") from None
    except TenantUnreachable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None


async def _call_tenant(gw, method: str, path: str, *, tenant_id: str, json=None) -> httpx.Response:
    """Send one request to a tenant's gateway, turning a transport failure into 503.

    `_gateway_for` above is careful to separate "no such tenant" (404) from "known but its
    credential could not be fetched" (503) — and then every call site threw that care away by
    awaiting `gw.request` bare. A DNS blip, a refused connection or a timeout reaching the
    tenant escaped as a raw `httpx.ConnectError`, which FastAPI renders as **500 with a stack
    trace in the log**. An operator reading that concludes the console is broken; the truth is
    that the tenant is unreachable and the next attempt will very likely work.

    Observed live on 2026-08-31: a provider raise against tenant1 returned Internal Server
    Error from `[Errno -5] No address associated with hostname`, and the same call succeeded
    on retry minutes later.

    503 is the same answer `_gateway_for` already gives for the other half of "we could not
    ask", so the two failures an operator cannot act on differently do not arrive as different
    status codes. The tenant is named in the message because a console reaching several
    tenants must say WHICH one is unreachable.
    """
    try:
        return await gw.request(method, path, json=json) if json is not None else await gw.request(method, path)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not reach tenant {tenant_id!r}'s gateway: {exc}",
        ) from exc


@router.post("/support-requests")
async def raise_support_request(body: RaiseSupportRequestBody, request: Request, session=_provider_read) -> dict:
    """Raise a request against one tenant's gateway (ADR-0017 §7, §7b).

    The scope check runs **before** the tenant is resolved, so a refusal on authority reads
    as one rather than as a 404 about the tenant named alongside it.

    This is the only place the monitor constraint can be enforced. The tenant's gateway sees
    the provider's single `support:request` credential, not which provider operator is
    behind it, so it cannot tell a monitor's raise from an admin's — and the browser is not
    a gate. Narrowing the console's checkbox list without this check would be decoration.
    """
    subject = _provider_subject(session)
    allowed = requestable_scopes_for(session.get("provider_scopes"))
    if allowed is not None:
        above = sorted(set(body.requested_scopes) - allowed)
        if above:
            await record_request(
                request,
                "provider.support_request.raise",
                outcome=OUTCOME_DENIED,
                target=subject,
                tenant_id=body.tenant_id,
                reason="scope_above_role",
                requested_scopes=sorted(body.requested_scopes),
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    "This provider role may only request: "
                    + ", ".join(sorted(allowed))
                    + ". Refused: "
                    + ", ".join(above)
                ),
            )
    gw = await _gateway_for(request, body.tenant_id)
    payload = {
        "provider_subject": subject,
        "requested_scopes": body.requested_scopes,
        "justification": body.justification,
    }
    if body.public_key:
        payload["public_key"] = body.public_key
    try:
        resp = await _call_tenant(gw, "POST", "/support-requests", tenant_id=body.tenant_id, json=payload)
    except HTTPException as exc:
        # Audited before re-raising. Previously the transport error escaped from here, so the
        # `record_request` below never ran and a raise that failed on the network left **no
        # trace on either plane** — not in the provider's audit, and not in the tenant's, which
        # never saw the request at all. An attempt an operator made and an attempt they never
        # made must not look identical afterwards.
        await record_request(
            request,
            "provider.support_request.raise",
            outcome=OUTCOME_DENIED,
            target=subject,
            tenant_id=body.tenant_id,
            reason="tenant_unreachable",
            requested_scopes=sorted(body.requested_scopes),
            status=exc.status_code,
        )
        raise
    await record_request(
        request,
        "provider.support_request.raise",
        outcome=outcome_for(resp.status_code),
        target=subject,
        tenant_id=body.tenant_id,
        status=resp.status_code,
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=_detail(resp))
    return resp.json()


@router.get("/support-requests/{request_id}")
async def poll_support_request(request_id: str, tenant_id: str, request: Request, session=_provider_read) -> dict:
    """The raising session's own view. Not audited — a poll is a read, and the gateway's own
    approve/reject already recorded the decision that matters.

    ``tenant_id`` names which tenant's gateway this request was raised against — the caller
    already knows it, since it's the tenant it named on the raise. Delivering an approved
    credential is not a bare passthrough: it must land on *this* session, not just in the
    response body, or nothing else on this session can use it.

    Only one grant is tracked on the session today — raising a second request against a
    different tenant while one is already held overwrites it here. Holding grants for more
    than one tenant at once is deferred to the next slice, not solved by this one.
    """
    subject = _provider_subject(session)
    gw = await _gateway_for(request, tenant_id)
    resp = await _call_tenant(
        gw,
        "GET",
        f"/support-requests/{request_id}?provider_subject={quote(subject, safe='')}",
        tenant_id=tenant_id,
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=_detail(resp))
    body = resp.json()
    if body.get("status") == "approved" and body.get("credential"):
        sess = await current_session(request)
        if isinstance(sess, dict):
            sess["support_grant"] = {
                "tenant_id": tenant_id,
                "grant_id": body.get("grant_id"),
                "credential": body["credential"],
            }
            await _persist_session(request, sess)
    return body


@router.get("/support-grant")
async def current_support_grant(session=_provider_read) -> dict:
    """Whether this session currently holds a delegated support grant, its id and which
    tenant it is for — never the credential itself, which has no use to the browser and
    every use to an attacker."""
    grant = session.get("support_grant")
    if not isinstance(grant, dict) or not grant.get("credential"):
        return {"held": False}
    return {"held": True, "grant_id": grant.get("grant_id"), "tenant_id": grant.get("tenant_id")}


@router.delete("/support-grant")
async def release_support_grant(request: Request, session=_provider_read) -> dict:
    """End this session's own grant early. Idempotent, like the gateway's own revoke."""
    grant = session.get("support_grant")
    grant_id = grant.get("grant_id") if isinstance(grant, dict) else None
    tenant_id = grant.get("tenant_id") if isinstance(grant, dict) else None
    # Only report a grant as released once the revoke was actually sent — a grant_id
    # present without a tenant_id (nothing writes that shape today, but nothing checks it
    # either) must not be echoed back as released when no DELETE call was ever made.
    released = None
    if grant_id and tenant_id:
        gw = await _gateway_for(request, tenant_id)
        # Deliberately NOT swallowed so the local session can be cleared anyway. Dropping our
        # copy of the credential while the grant is still live on the tenant would report
        # "released" for a grant that is still usable and still attributed to this operator —
        # the console would be lying about the one thing a release is for. 503 says plainly
        # that nothing was revoked; the grant's own TTL and the tenant's revoke remain, and a
        # retry is the repair.
        await _call_tenant(gw, "DELETE", f"/support-grants/{grant_id}", tenant_id=tenant_id)
        released = grant_id
    sess = await current_session(request)
    if isinstance(sess, dict) and sess.pop("support_grant", None) is not None:
        await _persist_session(request, sess)
    await record_request(
        request,
        "provider.support_grant.release",
        outcome=OUTCOME_SUCCESS if released else OUTCOME_DENIED,
        target=_provider_subject(session),
        grant_id=grant_id,
    )
    return {"released": released}


def _detail(resp) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text
    return body.get("detail", resp.text) if isinstance(body, dict) else resp.text
