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

# --- Planes (ADR-0013 §2/§3) -------------------------------------------------
#
# Two populations, not one. A tenant user belongs to a single tenant and authenticates to
# that tenant's IdP; a provider operator is cross-tenant by design and authenticates to the
# provider's IdP. The plane is set **at login, from which IdP authenticated** — never from a
# request parameter — and is never mutated in-session, so there is no in-session path from
# tenant authority to provider authority (§3).
#
# The two login routes are deliberately separate endpoints rather than one route with a
# selector: with no `plane=` input there is nothing for a handler to forget to validate.

PLANE_TENANT = "tenant"
PLANE_PROVIDER = "provider"
PLANES = (PLANE_TENANT, PLANE_PROVIDER)

# Provider scopes are **BFF scopes** (§5) and never gateway scopes. The gateway's
# ROLE_SCOPES has no provider entry by design, so one of these arriving at a gateway would
# be silently ignored rather than refused — which is why they are kept in a closed
# vocabulary here, at the source.
#
#   provider:monitor      aggregate estate health; no tenant API access at all (§7)
#   provider:admin        the everyday debugging grant within a named tenant
#
# `provider:invoke` (ELEVATED — invoke a tool against a tenant's live device) and
# `provider:credentials` (ELEVATED, credential-bearing access to a named tenant) are both
# gone: `provider:credentials` was removed with its mechanism at ADR-0018 §6 (gateway
# repo); `provider:invoke` is removed here at ADR-0017 slice 6, along with the
# act-on-tenant/elevated-grant machinery it named a class of (`grants.py`, deleted). What a
# provider operator may eventually request against a tenant's gateway is ADR-0017's
# delegated support-grant scopes (slice 7) — a different vocabulary, not a re-mechanized
# version of this one, so it is not reintroduced speculatively here.
SCOPE_PROVIDER_MONITOR = "provider:monitor"
SCOPE_PROVIDER_ADMIN = "provider:admin"

PROVIDER_SCOPES: frozenset[str] = frozenset({SCOPE_PROVIDER_MONITOR, SCOPE_PROVIDER_ADMIN})


def provider_scopes_for_groups(groups, mapping: dict[str, str]) -> frozenset[str]:
    """Map provider-IdP groups to provider scopes. **No fallback**: an unmapped group
    grants nothing.

    This is the BFF-side twin of the gateway's per-issuer `group_roles` rule (ADR-0013
    §6a). A shared or defaulting table is an escalation primitive — a group name the
    operator never mapped quietly acquiring authority — and it is consulted for
    provider-plane logins *only*, so a tenant's own IdP admin cannot reach it by naming a
    group after the provider mapping.
    """
    out: set[str] = set()
    for group in groups or []:
        scope = mapping.get(group)
        if scope is None:
            continue
        if scope not in PROVIDER_SCOPES:
            # Closed range. Config cannot smuggle a gateway scope into the provider
            # vocabulary, and a typo fails loudly instead of granting nothing quietly.
            raise ValueError(
                f"provider group {group!r} maps to {scope!r}, which is not one of "
                f"{sorted(PROVIDER_SCOPES)} — provider mappings may only grant provider scopes"
            )
        out.add(scope)
    return frozenset(out)


def session_identity(session) -> str:
    """A stable identity for a session that carries its **plane**.

    `sub` is unique within an IdP, not across them: `admin` at the tenant IdP and `admin`
    at the provider IdP are two different humans. The gateway hit exactly this defect one
    layer down — `oidc:{sub}` put both on one line of a hash-chained audit — so anything
    here keyed on the subject (audit actor, cache, throttle) carries the plane too.
    """
    plane = (session or {}).get("plane") or PLANE_TENANT
    subject = (session or {}).get("sub") or (session or {}).get("role") or "unknown"
    return f"{plane}:{subject}"


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
    # "tenant" | "provider" (ADR-0013 §3). Absent on sessions written before the provider
    # plane existed, which read as tenant — the safe direction, since tenant is the plane
    # with no cross-tenant authority.
    plane: str
    provider_scopes: list[str]  # provider sessions only — BFF scopes, never gateway scopes
    groups: list[str]  # oidc sessions — as asserted by the IdP, mapped per plane
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


async def _persist_session(request: Request, session: dict) -> None:
    """Write a mutated session back to the store, under the store's own per-session lock.

    Used where a *read* path has a side effect — spending a single-use elevation. Kept
    small and local rather than shared with the provider router, because the two have
    different failure expectations: a route that cannot persist should fail, and this one
    must not turn a data-plane read into a 500 after the grant has already been handed out.
    """
    sid = sessions.current_sid(request)
    store = getattr(getattr(request.app, "state", None), "sessions", None)
    if not sid or store is None:  # pragma: no cover - a session-gated path always has both
        return
    async with store.lock(sid):
        await store.set(sid, session)
    sessions.cache(request, session)


async def deny_password_session(request: Request) -> None:
    """Refuse the local break-glass login on routes that hand back credentials.

    Password sessions proxy with the stack's **admin** gateway token, which carries every
    `backup:*` scope. So on a backup route the BFF's role gate is not one control among
    several — it is the only one, and admitting `admin` there would produce a complete
    credential dump with no step-up, no elevation and nothing in either audit chain naming a
    grant. Break-glass exists to repair a broken fleet, not to export one.

    **This means a lite/home deployment has no backup or restore in the console, and that is
    deliberate.** Lite runs the gateway in embedded mode with SSO off, so a password session
    is the only session it has — and embedded mode refuses every elevated grant anyway
    (ADR-0013 §11a: no shared store to consume single-use against), so there is no elevated
    path to fall back to either. Lite is a home tinkerer's test bed; backup is not part of
    what it is for, and the gateway's own `/v1/admin/backup` is still there for anyone who
    wants it with the API key. Loosening this gate to give Lite a backup button would hand
    every tenant-stack break-glass login a credential dump to buy a feature Lite does not
    need — so if that trade ever looks attractive, condition it on the deployment shape
    rather than widening the rule.
    """
    sess = await current_session(request)
    if sess and sess.get("kind") == "password":
        raise HTTPException(
            status_code=403,
            detail=(
                "The local break-glass login cannot export or restore backups: it proxies with "
                "the stack's admin token, so the request would carry every credential scope with "
                "no step-up behind it. Sign in through the IdP."
            ),
        )


async def upstream_bearer(request: Request) -> Optional[str]:
    """The token the BFF should present to the gateway for this request.

    OIDC session → the user's access token (per-user identity, F-30). Password session
    → None, so the GatewayClient falls back to its configured admin token.

    **A provider-plane session must never reach that fallback** (ADR-0013 §4/§5a legacy
    reasoning, still true). Returning ``None`` for one is not "no credential" — the
    ``GatewayClient`` carries the tenant stack's *admin* key as its default header, so a
    fall-through would present a provider operator to the tenant's gateway as gateway
    ``admin``. This fails closed rather than being avoided by convention upstream.

    ADR-0017 slice 6: the act-on-tenant/elevated-grant credential this used to select
    between is gone. `require_role` now refuses a provider-plane session before any relay
    call reaches here at all, so this branch should be unreachable — it stays as a second,
    independent fail-closed check rather than trusting that ordering, since a bearer
    function is exactly the place a reachability assumption paying off wrong would be worst.
    ADR-0017's replacement (a delegated, gateway-minted support grant) is slice 7.
    """
    sess = await current_session(request)
    if session_plane(sess) == PLANE_PROVIDER:
        raise HTTPException(
            status_code=403,
            detail=(
                "A provider session has no path to a tenant's gateway right now. ADR-0013's "
                "act-on-tenant grant was removed; its ADR-0017 replacement has not shipped yet."
            ),
        )
    if sess and sess.get("kind") == "oidc":
        return sess.get("access_token")
    return None


def session_plane(session) -> str:
    """The plane of a session. Absent → tenant, which is the safe default: it is the plane
    that carries no cross-tenant authority, so an old session cannot become a provider one
    by omission."""
    plane = (session or {}).get("plane")
    return plane if plane in PLANES else PLANE_TENANT


def require_role(*allowed: str):
    """Dependency factory for the **tenant data plane**.

    401 if no session; for password sessions, 403 unless the role is permitted. OIDC
    sessions pass through — the gateway is the authorization point.

    **ADR-0017 slice 6: a provider-plane session cannot reach this plane at all, for now.**
    ADR-0013 §4's act-on-tenant grant — the mechanism that used to let a provider session in
    here, one tenant at a time, on a discrete audited act — was removed along with the rest
    of that design (`grants.py` is gone). Its replacement is a tenant-delegated, gateway-
    minted support grant the provider polls for (ADR-0017), which is slice 7, not yet built.
    Refusing unconditionally here is deliberate: it fails closed rather than leave a gap
    where "the old gate is gone" quietly became "no gate at all."
    """

    async def _dep(request: Request) -> SessionInfo:
        sess = await current_session(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if session_plane(sess) == PLANE_PROVIDER:
            raise HTTPException(
                status_code=403,
                detail=(
                    "The tenant data plane is not reachable from a provider session right now. "
                    "ADR-0013's act-on-tenant grant was removed; its ADR-0017 replacement (a "
                    "support grant delegated by the tenant) has not shipped yet."
                ),
            )
        if sess.get("kind") == "oidc":
            # Authorization is delegated to the gateway (it sees the user's real scopes).
            return sess
        if allowed and sess.get("role") not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return sess

    return _dep


def require_provider_scope(*required: str):
    """Dependency factory for **provider-plane** routes.

    The mirror image of :func:`require_role`, and refusing the converse direction matters
    just as much: a tenant session must not reach a provider route however its IdP names
    its groups. Provider scopes are only ever written onto a session by a provider-plane
    login (§5).
    """

    async def _dep(request: Request) -> SessionInfo:
        sess = await current_session(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if session_plane(sess) != PLANE_PROVIDER:
            raise HTTPException(status_code=403, detail="Not a provider-plane session")
        held = set(sess.get("provider_scopes") or [])
        if required and not held.intersection(required):
            raise HTTPException(status_code=403, detail="Forbidden")
        return sess

    return _dep
