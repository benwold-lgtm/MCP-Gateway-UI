# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Provider-plane routes: acquiring, reading and ending an act-on-tenant grant.

ADR-0013 §4/§8. The mechanism lives in ``app.grants``; this module is the HTTP surface and
the audit. Both matter equally — a grant that is issued but not recorded is standing access
with paperwork, which is the thing §4 exists to prevent.

Every route here is provider-plane by construction: :func:`require_provider_scope` refuses a
tenant session outright, in the same way the tenant data plane refuses a provider session
without a grant. The wall is checked in both directions, at both ends.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..audit import OUTCOME_DENIED, OUTCOME_SUCCESS, record_request
from ..grants import GrantError, active_grant, authorize_act_on_tenant, release_act_on_tenant
from ..security import SCOPE_PROVIDER_ADMIN, require_provider_scope
from .. import sessions

router = APIRouter(prefix="/provider", tags=["provider"])

_provider_admin = Depends(require_provider_scope(SCOPE_PROVIDER_ADMIN))


class AuthorizeBody(BaseModel):
    justification: str = ""


def _public(grant) -> dict:
    """What the browser is told about a grant.

    The justification is **not** echoed back. It is evidence, it is already in the chain,
    and the operator who wrote it seconds ago does not need it read back — so it does not
    become a field some later view renders, caches or logs a second time.
    """
    return {"id": grant.id, "tenant": grant.tenant, "granted_at": grant.granted_at, "expires_at": grant.expires_at}


async def _persist(request: Request, session: dict) -> None:
    """Write the mutated session back to the store.

    Under the store's own lock, the way ``relay.refresh_oidc_access_token`` does: two
    authorizations racing must not leave a grant whose audit record says something else was
    issued. The lock is per-sid, so this serialises one operator's own tabs, not the estate.
    """
    sid = sessions.current_sid(request)
    if not sid:  # pragma: no cover - a session-gated route always has one
        return
    store = request.app.state.sessions
    async with store.lock(sid):
        await store.set(sid, session)
    sessions.cache(request, session)


@router.post("/tenants/{tenant}/authorize")
async def authorize(tenant: str, body: AuthorizeBody, request: Request, session=_provider_admin) -> dict:
    """Acquire act-on-tenant for one tenant, dropping whatever was held.

    §8's "renewal is a new act, not an extension": this always mints. Re-authorizing the
    same tenant produces a new id, records the new justification, and writes its own audit
    record — there is no branch that finds the live grant and pushes its expiry out.
    """
    previous = active_grant(session, now=time.time())
    try:
        grant = authorize_act_on_tenant(
            session,
            tenant=tenant,
            justification=body.justification,
            now=time.time(),
            lifetime=getattr(request.app.state.settings, "act_on_tenant_seconds", None) or 3600,
        )
    except GrantError as exc:
        # Recorded, not just refused. "Who was refused what" is the question an audit is
        # most often asked, and a provider operator attempting to act on a customer without
        # a justification is exactly the record worth having.
        await record_request(
            request, "provider.act_on_tenant.authorize", outcome=OUTCOME_DENIED, target=tenant, reason=str(exc)
        )
        raise HTTPException(status_code=400, detail=str(exc))

    if previous is not None and previous.id != grant.id:
        # The drop gets its own record. Without it a reader of the chain sees two grants
        # opening and none closing, which reads exactly like the accumulated ambient
        # authority §4 forbids — the opposite of what happened.
        await record_request(
            request,
            "provider.act_on_tenant.release",
            outcome=OUTCOME_SUCCESS,
            target=previous.tenant,
            grant=previous.id,
            reason="superseded",
        )
    await _persist(request, session)
    await record_request(
        request,
        "provider.act_on_tenant.authorize",
        outcome=OUTCOME_SUCCESS,
        target=grant.tenant,
        grant=grant.id,
        justification=grant.justification,
        expires_at=grant.expires_at,
    )
    return _public(grant)


@router.get("/act-on-tenant")
async def current(request: Request, session=_provider_admin) -> dict:
    """The live grant, or ``{"grant": None}``. A read, so it is deliberately not audited —
    and deliberately does not renew anything (§8's window is absolute)."""
    grant = active_grant(session, now=time.time())
    return _public(grant) if grant else {"grant": None}


@router.delete("/act-on-tenant")
async def release(request: Request, session=_provider_admin) -> dict:
    """End the act. The cheap half of §4: an operator who has finished should not carry the
    authority for the rest of the hour."""
    held = release_act_on_tenant(session)
    await _persist(request, session)
    if held is not None:
        await record_request(
            request,
            "provider.act_on_tenant.release",
            outcome=OUTCOME_SUCCESS,
            target=held.tenant,
            grant=held.id,
            reason="released",
        )
    return {"released": held.tenant if held else None}
