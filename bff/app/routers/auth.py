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

from ..oidc import OIDCError, make_pkce_pair
from ..security import PASSWORD_ROLE_SCOPES, current_session, resolve_role

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    password: str


@router.get("/config")
async def auth_config(request: Request) -> dict:
    """What login methods this BFF offers — lets the SPA show SSO and/or password."""
    s = request.app.state.settings
    return {
        "oidc_enabled": request.app.state.oidc is not None,
        "password_login": bool(s.ui_admin_password or s.ui_viewer_password),
    }


@router.post("/login")
async def login(request: Request, body: LoginBody) -> dict:
    role = resolve_role(request.app.state.settings, body.password)
    if role is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session.clear()
    request.session["role"] = role
    return {"role": role}


@router.post("/logout")
async def logout(request: Request) -> dict:
    request.session.clear()
    return {"status": "logged out"}


@router.get("/me")
async def me(request: Request) -> dict:
    """The signed-in identity + **effective scopes**, so the SPA gates views the same way
    for both session kinds. Password roles use the local break-glass bundle; OIDC sessions
    get their real per-user scopes from the gateway's whoami (relayed with the user token),
    so the UI and gateway can't drift (ADR-0007)."""
    sess = current_session(request)
    if not sess:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if sess.get("kind") == "password":
        role = sess.get("role") or "viewer"
        return {
            "kind": "password",
            "subject": f"local:{role}",
            "role": role,
            "scopes": PASSWORD_ROLE_SCOPES.get(role, []),
        }

    # OIDC: ask the gateway who this user is (it owns group→scope). Relay the user's token.
    scopes: list[str] = []
    subject = sess.get("sub") or "unknown"
    try:
        resp = await request.app.state.gateway.get("/auth/me", bearer=sess.get("access_token"))
    except Exception:
        resp = None
    if resp is not None and resp.status_code == 401:
        # The user's token was rejected (expired/revoked). End the session.
        request.session.clear()
        raise HTTPException(status_code=401, detail="Session expired")
    if resp is not None and resp.status_code == 200:
        data = resp.json()
        scopes = data.get("scopes", [])
        subject = data.get("subject", subject)
    # On any other upstream condition (e.g. an older gateway without /auth/me) we fall back
    # to no scopes: the SPA shows a read-only affordance while the gateway still authorizes
    # each actual call on the relayed token.
    return {"kind": "oidc", "subject": subject, "name": sess.get("name"), "role": None, "scopes": scopes}


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
        # state mismatch → possible CSRF/forged callback. Refuse.
        raise HTTPException(status_code=400, detail="OIDC state mismatch")

    try:
        tokens = await oidc.exchange_code(code=code, verifier=tx["verifier"])
        claims = await oidc.validate_id_token(id_token=tokens["id_token"], nonce=tx["nonce"])
    except OIDCError as exc:
        raise HTTPException(status_code=401, detail=f"OIDC login failed: {exc}")

    # Establish the session. Rotate it (clear first) so the pre-login session id can't be
    # fixated, and store the access token server-side for the upstream relay.
    request.session.clear()
    request.session["auth"] = {
        "kind": "oidc",
        "sub": claims.get("sub"),
        "name": claims.get("name") or claims.get("preferred_username") or claims.get("email"),
        "access_token": tokens.get("access_token"),
    }
    return RedirectResponse(request.app.state.settings.oidc_post_login_redirect or "/", status_code=302)
