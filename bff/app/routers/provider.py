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

import secrets

from ..audit import OUTCOME_DENIED, OUTCOME_SUCCESS, record_request
from ..grants import (
    GrantError,
    active_elevated_grant,
    active_grant,
    authorize_act_on_tenant,
    drop_elevated_grant,
    elevated_spec,
    release_act_on_tenant,
    step_up_scopes,
)
from ..oidc import make_pkce_pair
from ..security import SCOPE_PROVIDER_ADMIN, require_provider_scope
from .. import sessions

router = APIRouter(prefix="/provider", tags=["provider"])

_provider_admin = Depends(require_provider_scope(SCOPE_PROVIDER_ADMIN))


class AuthorizeBody(BaseModel):
    justification: str = ""


class ElevateBody(BaseModel):
    scope: str = ""
    justification: str = ""


#: Where the step-up transaction lives in the signed cookie session. Distinct from the
#: login transaction key so a step-up in flight cannot be completed by a login callback or
#: the reverse — the plane's own lesson, applied one level in.
STEP_UP_TX = "provider_step_up_tx"


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


@router.get("/tenants")
async def tenants(request: Request, session=_provider_admin) -> dict:
    """The estate this operator may act on, and which of it this console can reach.

    Read-only and unaudited, like the other two reads here: an operator looking at a list of
    tenants has not touched any of them, and a route that wrote to the chain on every render
    would bury the acts that matter under navigation.

    **Two independent facts, reported separately rather than resolved into one list**, because
    each is invisible on its own and an operator who cannot see them will assume the opposite:

    * ``entitled`` — what the *directory* said at login. `null` means the IdP published no
      estate (a mapper is missing); `[]` means it published an empty one. Different problems,
      different fixes, so they are not collapsed.
    * ``served`` — the single tenant this BFF's gateway *is*. Today a deployment serves one
      tenant (`settings.tenant_id`), so every other entitled tenant is a legitimate act that
      currently reaches no devices: `require_tenant_plane` refuses the relay when the grant
      names anything else. Reaching N gateways is slice 3.

    Deliberately **not** filtered to the intersection. Hiding the unreachable tenants would
    make the console look like it disagreed with the directory, and would teach an operator
    that their estate is one tenant when it is not. The console shows both and says which is
    which; the refusal stays where it can be enforced.

    Nothing here authorizes anything. §11c is explicit that the tenant intersection belongs
    to the gateway, so this list can only ever change what is *offered*, never what is
    *accepted* — a caller that ignores it entirely and posts a tenant by hand gets exactly
    the same answer from `authorize` and from the gateway.
    """
    settings = request.app.state.settings
    return {
        "entitled": session.get("entitled_tenants"),
        "served": getattr(settings, "tenant_id", "") or None,
    }


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


# --- the elevated grant (ADR-0013 §5a/§8/§11b) ---------------------------------
#
# Two routes, because a step-up is a round trip through the IdP: one to start it, one to
# receive what came back. The verification that matters happens in the second — the first
# only *asks*, and asking proves nothing.


def step_up_ready(request: Request):
    """The provider RP and step-up context, or a 404.

    404 rather than 500: with no configured `acr` there is no context to verify, so the
    elevated grants are not *broken* here, they are not offered. Offering them
    unverifiable is the state §11b's constraint exists to prevent.
    """
    settings = request.app.state.settings
    oidc = request.app.state.provider_oidc
    if oidc is None or not settings.provider_step_up_acr or not settings.provider_step_up_redirect_url:
        raise HTTPException(
            status_code=404,
            detail=(
                "Elevated grants are not available on this BFF: PROVIDER_STEP_UP_ACR and "
                "PROVIDER_STEP_UP_REDIRECT_URL must both be set so the step-up can be verified "
                "(ADR-0013 §11b)."
            ),
        )
    return oidc, settings


@router.post("/tenants/{tenant}/elevate")
async def elevate(tenant: str, body: ElevateBody, request: Request, session=_provider_admin) -> dict:
    """Begin a step-up for one elevated grant on one tenant.

    Everything checkable *before* the round trip is checked here, so an operator is not
    sent through an MFA prompt only to be refused on the way back — and so a refusal is
    recorded against the act that prompted it rather than against a returning callback.
    """
    oidc, settings = step_up_ready(request)
    try:
        spec = elevated_spec(body.scope)
        justification = body.justification.strip()
        if not justification:
            raise GrantError(
                "an elevated grant requires a justification (ADR-0013 §8) — it is the only record "
                "of why a customer's hardware or credentials were reached"
            )
        act = active_grant(session, now=time.time())
        if act is None or act.tenant != tenant:
            raise GrantError(
                f"an elevated grant requires a live act-on-tenant grant for {tenant!r}; "
                f"authorize the act first (ADR-0013 §4/§8)"
            )
        # §11c: resolved here rather than at the redirect, so a deployment that has not
        # configured the template is refused *before* an operator is sent through a second
        # factor for a step-up that could only ever come back without a grant claim.
        scopes = step_up_scopes(settings.provider_step_up_scope_template, tenant=tenant, provider_scope=body.scope)
    except GrantError as exc:
        await record_request(request, "provider.elevate", outcome=OUTCOME_DENIED, target=tenant, reason=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = make_pkce_pair()
    # The tenant, scope and justification ride in the server-side transaction, never in the
    # URL: they are what the callback will record, and a callback that took them from the
    # query string would let a redirected round trip re-aim the elevation at another tenant.
    request.session[STEP_UP_TX] = {
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
        "tenant": tenant,
        "scope": body.scope,
        "justification": justification,
        "act": act.id,
    }
    url = await oidc.authorization_url(
        state=state,
        nonce=nonce,
        challenge=challenge,
        acr_values=settings.provider_step_up_acr,
        # `max_age=0` asks the IdP to re-authenticate rather than reuse a live session.
        # §8 spends a step-up here precisely because this is where a stolen session cashes
        # out — reusing the session it was stolen with would defeat the point.
        max_age=0,
        redirect_uri=settings.provider_step_up_redirect_url,
        extra_scopes=scopes,
    )
    _ = spec  # validated above; the spec itself is re-derived from the transaction
    return {"authorization_url": url}


@router.get("/elevation")
async def current_elevation(request: Request, session=_provider_admin) -> dict:
    """The live elevation, or ``{"elevation": None}``.

    Read-only and unaudited, for the same reason :func:`current` is: a console polling a
    countdown must not write to the chain, and must not renew what it is displaying.

    An elevation is authority over one tenant, so it is only ever reported *for the tenant
    currently being acted on* — with no live act there is nothing to report even if the
    session still holds a grant record. That mirrors :func:`grants.active_elevated_grant`,
    which refuses to answer without being told which tenant is being asked about, and it
    keeps the console from showing an elevation that no route would honour.

    ``single_use`` is in the payload because it is the field that makes this state visibly
    different from an invoke elevation: one spends on the next operation, the other lasts
    its window. A console that rendered both as "elevated until 12:04" would be describing
    the credentials grant wrongly.
    """
    now = time.time()
    act = active_grant(session, now=now)
    grant = active_elevated_grant(session, tenant=act.tenant, now=now) if act is not None else None
    if grant is None:
        return {"elevation": None}
    # Same omissions as the step-up callback's own response: never the token, never the
    # justification. Both are already recorded; neither is something a view needs.
    return {
        "id": grant.id,
        "tenant": grant.tenant,
        "scope": grant.provider_scope,
        "granted_at": grant.granted_at,
        "expires_at": grant.expires_at,
        "single_use": grant.single_use,
    }


@router.delete("/elevation")
async def end_elevation(request: Request, session=_provider_admin) -> dict:
    """Drop any elevation without ending the act beneath it."""
    held = drop_elevated_grant(session)
    await _persist(request, session)
    if held is not None:
        await record_request(
            request,
            "provider.elevate.release",
            outcome=OUTCOME_SUCCESS,
            target=held.tenant,
            grant=held.id,
            scope=held.provider_scope,
        )
    return {"released": held.id if held else None}
