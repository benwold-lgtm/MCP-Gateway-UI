# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Session model and authorization for the BFF.

Two kinds of session (ADR-0007):

* **password** — local break-glass/bootstrap login. The BFF proxies upstream with the
  single **admin** gateway token, so the BFF's role check is *load-bearing*: a `viewer`
  password must not be able to mutate via the all-powerful admin token. Role gating here
  stays exactly as before.
* **oidc** — federated login. The BFF relays the **user's own** access token upstream
  (Mode A token passthrough), so the **gateway** authorizes on the user's real scopes.
  The BFF therefore does **not** re-authorize (no BFF-side authz is load-bearing for OIDC,
  per the threat model) — it only requires that a session exists.

Session content (the password role; for OIDC the user's tokens) lives in the
server-side store (:mod:`app.sessions`) — the browser cookie carries only an opaque
signed session id. No token or role ever reaches the browser.
"""

from __future__ import annotations

import hmac
from typing import Optional, TypedDict

from fastapi import HTTPException, Request

from . import sessions

ROLES = ("admin", "viewer")

# Scope bundles for the local **break-glass** password roles, mirroring the gateway's
# admin/viewer bundles. These exist only so the UI can gate the same way for both session
# kinds; password sessions proxy with the admin token, and the BFF's role gate (not these
# scopes) is what actually enforces them. OIDC sessions get their scopes from the gateway's
# /auth/me instead (the real per-user grant), so there is no duplicated mapping for them.
PASSWORD_ROLE_SCOPES: dict[str, list[str]] = {
    "admin": ["devices:read", "devices:write", "metrics:read", "tools:call"],
    "viewer": ["devices:read", "metrics:read"],
}


class SessionInfo(TypedDict, total=False):
    kind: str  # "password" | "oidc"
    role: str  # password sessions
    sub: str  # oidc sessions — IdP subject
    name: str  # oidc sessions — display name
    access_token: str  # oidc sessions — relayed upstream
    refresh_token: str  # oidc sessions — server-side only, used for silent refresh
    id_token: str  # oidc sessions — id_token_hint for RP-initiated logout


def resolve_role(settings, password: str) -> Optional[str]:
    """Map a login password to a role using constant-time comparison."""
    if settings.ui_admin_password and hmac.compare_digest(password, settings.ui_admin_password):
        return "admin"
    if settings.ui_viewer_password and hmac.compare_digest(password, settings.ui_viewer_password):
        return "viewer"
    return None


async def current_session(request: Request) -> Optional[SessionInfo]:
    """The authenticated session from the server-side store, or None."""
    data = await sessions.load(request)
    if isinstance(data, dict) and data.get("kind") in ("password", "oidc"):
        return data  # type: ignore[return-value]
    return None


async def current_role(request: Request) -> Optional[str]:
    """The legacy role accessor — only meaningful for password sessions."""
    sess = await current_session(request)
    if sess and sess.get("kind") == "password":
        return sess.get("role")
    return None


async def upstream_bearer(request: Request) -> Optional[str]:
    """The token the BFF should present to the gateway for this request.

    OIDC session → the user's access token (per-user identity, F-30). Password session
    → None, so the GatewayClient falls back to its configured admin token.
    """
    sess = await current_session(request)
    if sess and sess.get("kind") == "oidc":
        return sess.get("access_token")
    return None


def require_role(*allowed: str):
    """Dependency factory: 401 if no session; for password sessions, 403 unless the role
    is permitted. OIDC sessions pass through — the gateway is the authorization point."""

    async def _dep(request: Request) -> SessionInfo:
        sess = await current_session(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if sess.get("kind") == "oidc":
            # Authorization is delegated to the gateway (it sees the user's real scopes).
            return sess
        if allowed and sess.get("role") not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return sess

    return _dep
