# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Login / logout / whoami.

Two ways in (ADR-0007):
  * **password** — local break-glass/bootstrap login (admin / viewer), unchanged.
  * **oidc** — federated SSO via Authorization Code + PKCE; the BFF holds the user's
    tokens server-side and relays the access token upstream.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from .. import sessions
from ..audit import OUTCOME_DENIED, OUTCOME_SUCCESS, record_request
from ..oidc import OIDCError, make_pkce_pair
from ..relay import relay_get
from ..security import (
    PASSWORD_ROLE_SCOPES,
    PLANE_PROVIDER,
    PLANE_TENANT,
    current_session,
    provider_scopes_for_groups,
    resolve_role,
    session_plane,
)
from ..throttle import client_ip

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    password: str


@router.get("/config")
async def auth_config(request: Request) -> dict:
    """What login methods this BFF offers — lets the SPA show SSO and/or password.

    ``provider_enabled`` is what tells the SPA it is attached to a **provider console**
    rather than a tenant one. Note what it is not: a plane selector. ``create_app`` refuses
    to start with both IdPs configured (§2/§5), so this is mutually exclusive with
    ``oidc_enabled`` by construction — the deployment decides the plane, and the browser
    only reads which deployment it reached. A UI that offered the operator the choice would
    be re-introducing at the front door the thing the startup check exists to forbid.

    ``catalog_enabled`` answers "does this deployment take part in a catalog estate at all",
    NOT "is the catalog reachable right now". The distinction is the one
    `CatalogClient.configured` already draws: *a deployment with no catalog configured is a
    supported arrangement, not a degraded one.* Lite and plain single-tenant installs have no
    `TENANT_ID`, so `_tenant_id` fails every catalog route closed — offering them a "Claim from
    catalog" button meant a home user's main onboarding screen answered with
    `TENANT_ID not configured on this BFF`, a multi-tenancy error naming a variable their
    edition does not have.

    Keyed on `tenant_id` rather than on `catalog.configured`, for two reasons. It is the
    condition that actually decides whether the flow can *ever* work here, rather than whether
    it works this second — an enrolled tenant whose catalog is down should still see the
    button and get the named 503, because that is a real outage rather than an unsupported
    arrangement. And gating on `configured` would deadlock: the catalog address is learned
    lazily on first use (ADR-0024 §10), so hiding the button until it resolves means nothing
    ever asks, and it never resolves.
    """
    s = request.app.state.settings
    return {
        "oidc_enabled": request.app.state.oidc is not None,
        "password_login": bool(s.ui_admin_password or s.ui_viewer_password),
        "provider_enabled": request.app.state.provider_oidc is not None,
        "catalog_enabled": bool(s.tenant_id) and not s.provider_oidc_enabled,
    }


@router.post("/login")
async def login(request: Request, body: LoginBody) -> dict:
    settings = request.app.state.settings
    throttle = request.app.state.login_throttle
    ip = client_ip(request, trusted_cidrs=request.app.state.trusted_proxy_cidrs)

    # Refuse before touching the password once this IP has failed too many times recently
    # (review #3) — brute-force protection the constant-time compare alone can't provide.
    locked = throttle.retry_after(ip)
    if locked:
        # Audited: a lockout is the signal that someone is being brute-forced, and it is
        # invisible in the gateway's chain because the request never reaches the gateway.
        await record_request(request, "auth.login", outcome=OUTCOME_DENIED, reason="throttled", ip=ip)
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts; try again later",
            headers={"Retry-After": str(locked)},
        )

    role = resolve_role(settings, body.password)
    if role is None:
        throttle.record_failure(ip)
        await record_request(request, "auth.login", outcome=OUTCOME_DENIED, reason="bad_credentials", ip=ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    throttle.record_success(ip)  # clear this IP's failure streak on success
    # Break-glass password login is tenant-plane by construction. There is no field in
    # the body that can change that: the provider console is not reachable with a local
    # password (ADR-0013 §2 — provider operators authenticate to the provider IdP).
    await sessions.establish(request, {"kind": "password", "role": role, "plane": PLANE_TENANT})
    # Recorded after establish() so the actor resolves to the session just created rather
    # than to "unauthenticated" — the record should name who got in, not who asked.
    await record_request(request, "auth.login", outcome=OUTCOME_SUCCESS, target=role, ip=ip, method="password")
    return {"role": role}


@router.post("/logout")
async def logout(request: Request) -> dict:
    """Clear the local session. For an OIDC session, also return the IdP's RP-initiated
    logout URL (when the IdP exposes one) so the SPA can end the IdP session too —
    otherwise "Sign in with SSO" silently logs the user straight back in."""
    sess = await current_session(request)
    # The RP that authenticated this session, **selected by its plane**. Reading
    # `state.oidc` unconditionally was a real defect: a provider console leaves `OIDC_*`
    # unset (§2/§5 — a BFF refuses to carry both IdPs), so `state.oidc` is None there, the
    # branch below never ran, and sign-out ended the local session while leaving the
    # provider IdP's cookie intact. The next "Sign in with the provider directory" was then
    # silent SSO — no credentials, no prompt — which on *this* plane hands the next person
    # at that browser cross-tenant authority. Found in a browser; every logout test passed
    # throughout, because they only ever exercised the tenant plane.
    oidc = request.app.state.provider_oidc if session_plane(sess) == PLANE_PROVIDER else request.app.state.oidc
    end_session_url: str | None = None
    if sess and sess.get("kind") == "oidc" and oidc is not None and sess.get("id_token"):
        try:
            end_session_url = await oidc.end_session_url(
                id_token_hint=sess["id_token"],
                post_logout_redirect_uri=request.app.state.settings.oidc_post_logout_redirect or None,
            )
        except Exception:
            end_session_url = None  # IdP unreachable → local-only logout
    # Before destroy(), so the actor is still resolvable from the session being ended.
    await record_request(request, "auth.logout", outcome=OUTCOME_SUCCESS, method=(sess or {}).get("kind"))
    await sessions.destroy(request)
    return {"status": "logged out", "end_session_url": end_session_url}


@router.get("/me")
async def me(request: Request) -> dict:
    """The signed-in identity + **effective scopes**, so the SPA gates views the same way
    for both session kinds. Password roles use the local break-glass bundle; OIDC sessions
    get their real per-user scopes from the gateway's whoami (relayed with the user token),
    so the UI and gateway can't drift (ADR-0007)."""
    sess = await current_session(request)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")

    plane = session_plane(sess)

    if plane == PLANE_PROVIDER:
        # A provider session carries provider scopes and NO tenant-plane authority. The
        # two vocabularies are reported separately so the SPA cannot render one as the
        # other — a combined "scopes" list would invite exactly that (§5).
        return {
            "kind": sess.get("kind", "oidc"),
            "plane": PLANE_PROVIDER,
            "subject": sess.get("sub") or "unknown",
            "name": sess.get("name"),
            "role": None,
            "scopes": [],
            "provider_scopes": sorted(sess.get("provider_scopes") or []),
        }

    if sess.get("kind") == "password":
        role = sess.get("role") or "viewer"
        return {
            "kind": "password",
            "plane": PLANE_TENANT,
            "subject": f"local:{role}",
            "role": role,
            "scopes": PASSWORD_ROLE_SCOPES.get(role, []),
            "provider_scopes": [],
        }

    # OIDC: ask the gateway who this user is (it owns group→scope). The relay forwards the
    # user's token and, on a 401, silently refreshes it once before we give up (review #4).
    scopes: list[str] = []
    subject = sess.get("sub") or "unknown"
    try:
        resp = await relay_get(request, "/auth/me")
    except Exception:
        resp = None
    if resp is not None and resp.status_code == 401:
        # Token rejected and refresh did not recover it (expired/revoked, or no refresh
        # token). End the session.
        await sessions.destroy(request)
        raise HTTPException(status_code=401, detail="Session expired")
    if resp is not None and resp.status_code == 200:
        data = resp.json()
        scopes = data.get("scopes", [])
        subject = data.get("subject", subject)
    # On any other upstream condition (e.g. an older gateway without /auth/me) we fall back
    # to no scopes: the SPA shows a read-only affordance while the gateway still authorizes
    # each actual call on the relayed token.
    return {
        "kind": "oidc",
        "plane": PLANE_TENANT,
        "subject": subject,
        "name": sess.get("name"),
        "role": None,
        "scopes": scopes,
        # Always empty on the tenant plane, and stated rather than omitted: a client that
        # reads a missing key as "unknown" should read it as "none".
        "provider_scopes": [],
    }


# --- OIDC (Authorization Code + PKCE) ----------------------------------------


@router.get("/oidc/login")
async def oidc_login(request: Request) -> RedirectResponse:
    oidc = request.app.state.oidc
    if oidc is None:
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = make_pkce_pair()
    # The transaction secrets live in the (signed, HttpOnly) session — never the URL —
    # and are single-use: the callback pops them. Defeats login-CSRF (TM-I-01).
    request.session["oidc_tx"] = {"state": state, "nonce": nonce, "verifier": verifier}
    url = await oidc.authorization_url(state=state, nonce=nonce, challenge=challenge)
    return RedirectResponse(url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    oidc = request.app.state.oidc
    if oidc is None:
        raise HTTPException(status_code=404, detail="OIDC is not enabled")

    tx = request.session.pop("oidc_tx", None)
    if error:
        raise HTTPException(status_code=400, detail=f"IdP returned an error: {error}")
    if not code or not state or not isinstance(tx, dict):
        raise HTTPException(status_code=400, detail="Invalid OIDC callback")
    if not secrets.compare_digest(state, tx.get("state", "")):
        # state mismatch → possible CSRF/forged callback. Refuse — and record it, because a
        # forged callback is an attack signal, not a user error.
        await record_request(request, "auth.oidc_login", outcome=OUTCOME_DENIED, reason="state_mismatch")
        raise HTTPException(status_code=400, detail="OIDC state mismatch")

    try:
        tokens = await oidc.exchange_code(code=code, verifier=tx["verifier"])
        claims = await oidc.validate_id_token(
            id_token=tokens["id_token"], nonce=tx["nonce"], access_token=tokens.get("access_token")
        )
    except OIDCError as exc:
        await record_request(request, "auth.oidc_login", outcome=OUTCOME_DENIED, reason="token_exchange_failed")
        raise HTTPException(status_code=401, detail=f"OIDC login failed: {exc}")

    # Establish the session in the server-side store (establish() mints a fresh sid, so
    # a pre-login session id can't be fixated). The tokens never enter the cookie; the
    # id_token is kept as the id_token_hint for RP-initiated logout.
    await sessions.establish(
        request,
        {
            "kind": "oidc",
            # Set from WHICH IdP authenticated, never from the request (§3). This handler
            # is reachable only from the tenant IdP's callback, so the plane is structural.
            "plane": PLANE_TENANT,
            "sub": claims.get("sub"),
            "name": claims.get("name") or claims.get("preferred_username") or claims.get("email"),
            "access_token": tokens.get("access_token"),
            "id_token": tokens.get("id_token"),
            # Used to silently refresh the access token (review #4). Present only when
            # the IdP issued one (e.g. the offline_access scope was granted).
            "refresh_token": tokens.get("refresh_token"),
        },
    )
    # After establish(), so the actor is the federated subject rather than "unauthenticated".
    await record_request(request, "auth.oidc_login", outcome=OUTCOME_SUCCESS, method="oidc")
    return RedirectResponse(request.app.state.settings.oidc_post_login_redirect or "/", status_code=302)


# --- Provider plane (ADR-0013 §2/§3) -----------------------------------------
#
# A second, structurally separate login. Separate endpoints rather than a `plane=`
# parameter on the existing ones: with no selector in the request there is nothing for a
# handler to forget to validate, and the plane of a session is a fact about which IdP
# authenticated rather than something a caller asserted.


@router.get("/provider/login")
async def provider_login(request: Request) -> RedirectResponse:
    oidc = request.app.state.provider_oidc
    if oidc is None:
        raise HTTPException(status_code=404, detail="The provider plane is not enabled on this BFF")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = make_pkce_pair()
    # A separate transaction key, so a tenant login in flight cannot be completed by a
    # provider callback or the reverse — the plane is fixed from the first redirect.
    request.session["provider_oidc_tx"] = {"state": state, "nonce": nonce, "verifier": verifier}
    url = await oidc.authorization_url(state=state, nonce=nonce, challenge=challenge)
    return RedirectResponse(url, status_code=302)


@router.get("/provider/callback")
async def provider_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    oidc = request.app.state.provider_oidc
    if oidc is None:
        raise HTTPException(status_code=404, detail="The provider plane is not enabled on this BFF")

    tx = request.session.pop("provider_oidc_tx", None)
    if error:
        raise HTTPException(status_code=400, detail=f"IdP returned an error: {error}")
    if not code or not state or not isinstance(tx, dict):
        raise HTTPException(status_code=400, detail="Invalid OIDC callback")
    if not secrets.compare_digest(state, tx.get("state", "")):
        await record_request(request, "auth.provider_login", outcome=OUTCOME_DENIED, reason="state_mismatch")
        raise HTTPException(status_code=400, detail="OIDC state mismatch")

    try:
        tokens = await oidc.exchange_code(code=code, verifier=tx["verifier"])
        claims = await oidc.validate_id_token(
            id_token=tokens["id_token"], nonce=tx["nonce"], access_token=tokens.get("access_token")
        )
    except OIDCError as exc:
        await record_request(request, "auth.provider_login", outcome=OUTCOME_DENIED, reason="token_exchange_failed")
        raise HTTPException(status_code=401, detail=f"OIDC login failed: {exc}")

    settings = request.app.state.settings
    groups = claims.get(settings.provider_groups_claim) or []
    if isinstance(groups, str):  # some IdPs emit a single group as a bare string
        groups = [groups]
    # Mapped here, on the provider-plane path only. There is no shared table a tenant
    # login could reach by naming a group after the provider mapping (§6a's rule, this side).
    scopes = provider_scopes_for_groups(groups, settings.provider_group_scopes)
    if not scopes:
        # Authenticated but unmapped: a session with no provider authority. Every provider
        # route then 403s and the audit names who was refused — better than a blank 401
        # that hides the identity.
        await record_request(
            request, "auth.provider_login", outcome=OUTCOME_DENIED, reason="no_mapped_group", method="oidc"
        )

    await sessions.establish(
        request,
        {
            "kind": "oidc",
            # Structural: this handler is reachable only from the provider IdP's callback.
            "plane": PLANE_PROVIDER,
            "sub": claims.get("sub"),
            "name": claims.get("name") or claims.get("preferred_username") or claims.get("email"),
            "provider_scopes": sorted(scopes),
            # The operator's own token, kept so the BFF has an accountable identity — though
            # as of ADR-0017 slice 6 there is no path that currently relays it anywhere
            # (`require_role` refuses every provider-plane session before any tenant-plane
            # relay call; see `security.py`). Kept rather than dropped because slice 7's
            # replacement mechanism will need exactly this: an accountable operator identity
            # to present when raising a support request against a named tenant's gateway.
            "access_token": tokens.get("access_token"),
            "id_token": tokens.get("id_token"),
        },
    )
    await record_request(request, "auth.provider_login", outcome=OUTCOME_SUCCESS, method="oidc")
    return RedirectResponse(settings.oidc_post_login_redirect or "/", status_code=302)
