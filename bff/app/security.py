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
from typing import Any, Optional, TypedDict

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
    # `support:administer` (ADR-0017 §7, slice 7) gates `/api/support/*` and
    # `/api/notifications` via `require_role("admin")` — included here so the same
    # password-admin session that the BFF actually admits also sees the nav item for it,
    # rather than the UI hiding a control the backend would honour.
    "admin": ["devices:read", "devices:write", "metrics:read", "tools:call", "support:administer"],
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
    # ADR-0017 slice 7 — a delegated support grant a provider session polled from a tenant's
    # own gateway: {"tenant_id": str, "grant_id": str, "credential": str}. `tenant_id` (added
    # ADR-0021 scoped slice 3) is what `relay._gateway_for` resolves against the tenant
    # gateway pool — a provider console can reach more than one tenant, so the credential
    # alone no longer says where to send it. No expiry or scope list is cached here on
    # purpose (see `security.upstream_bearer`'s docstring) — the gateway checks the
    # credential live on every request, and the BFF follows that same posture rather than
    # keeping a second, potentially-stale opinion about whether it is still good or what it
    # covers. Only one grant is held per session today — raising against a second tenant
    # overwrites this rather than adding a second entry (`routers/provider.py`).
    support_grant: dict


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

    **A provider-plane session must never reach that fallback** (still true — falling
    through would present a provider operator to the tenant's gateway as gateway ``admin``,
    holding every scope and attributable to nobody). A provider session instead presents its
    own delegated support grant (ADR-0017 §7) — the credential polled from the tenant's
    gateway once a tenant admin approved a raised request. `require_role` already refused
    the request if none was held, so this is a second, independent fail-closed check rather
    than trusting that ordering — a bearer function is exactly the place a reachability
    assumption paying off wrong would be worst.
    """
    sess = await current_session(request)
    if session_plane(sess) == PLANE_PROVIDER:
        credential = _support_grant_credential(sess)
        if credential is None:
            raise HTTPException(
                status_code=403,
                detail=(
                    "A provider session has no delegated support grant to present to this "
                    "tenant's gateway (ADR-0017 §7). It is never relayed with the stack's admin key."
                ),
            )
        return credential
    if sess and sess.get("kind") == "oidc":
        return sess.get("access_token")
    return None


def session_plane(session) -> str:
    """The plane of a session. Absent → tenant, which is the safe default: it is the plane
    that carries no cross-tenant authority, so an old session cannot become a provider one
    by omission."""
    plane = (session or {}).get("plane")
    return plane if plane in PLANES else PLANE_TENANT


def _support_grant_credential(session: Any) -> Optional[str]:
    """The bearer of a provider session's delegated support grant, or `None` (ADR-0017 §7).

    Deliberately does not check an expiry against the BFF's own clock: the gateway checks
    this credential live on every request it receives (`SupportGrantStore.check`), never
    caching an opinion about whether it is still good — so the BFF matches that posture
    rather than keeping a second, potentially-stale one. A dead credential is discovered the
    same way here as everywhere else in this design: the next relayed call 401s, and the
    caller (`relay_get`/`relay_request`) clears it from the session at that point.
    """
    grant = (session or {}).get("support_grant") if isinstance(session, dict) else None
    if not isinstance(grant, dict):
        return None
    credential = grant.get("credential")
    return credential if isinstance(credential, str) and credential else None


def require_role(*allowed: str):
    """Dependency factory for the **tenant data plane**.

    401 if no session; for password sessions, 403 unless the role is permitted. OIDC
    sessions pass through — the gateway is the authorization point.

    **A provider-plane session reaches this plane only while holding a delegated support
    grant (ADR-0017 §7).** ADR-0013's act-on-tenant grant — a provider session asserting its
    own authority over a named tenant — is removed (`grants.py` is gone, ADR-0017 slice 6);
    what replaces it is the tenant's own gateway minting a credential once a tenant admin
    approves a request the provider raised (slice 7). This dependency only checks that
    *something* was polled — the credential's actual scopes are enforced by the gateway on
    every relayed call, same as an OIDC tenant session.
    """

    async def _dep(request: Request) -> SessionInfo:
        sess = await current_session(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if session_plane(sess) == PLANE_PROVIDER:
            if _support_grant_credential(sess) is None:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "This provider session holds no delegated support grant for this tenant's "
                        "gateway. Raise a support request and wait for the tenant to approve it "
                        "(ADR-0017 §7)."
                    ),
                )
            return sess
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
