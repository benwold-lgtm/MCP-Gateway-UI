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
import time
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
#   provider:invoke       ELEVATED — invoke a tool against a tenant's live device
#   provider:credentials  ELEVATED — credential-bearing access to a named tenant
#
# The two elevated grants are time-boxed, individually justified and separately audited
# (§5a/§8); they are not reachable by widening a group mapping.
SCOPE_PROVIDER_MONITOR = "provider:monitor"
SCOPE_PROVIDER_ADMIN = "provider:admin"
SCOPE_PROVIDER_INVOKE = "provider:invoke"
SCOPE_PROVIDER_CREDENTIALS = "provider:credentials"

PROVIDER_SCOPES: frozenset[str] = frozenset(
    {SCOPE_PROVIDER_MONITOR, SCOPE_PROVIDER_ADMIN, SCOPE_PROVIDER_INVOKE, SCOPE_PROVIDER_CREDENTIALS}
)

# Elevated grants are never handed out by a group mapping — see §5a. Mapping a group
# straight to one would rebuild the ambient authority §4 exists to remove.
ELEVATED_PROVIDER_SCOPES: frozenset[str] = frozenset({SCOPE_PROVIDER_INVOKE, SCOPE_PROVIDER_CREDENTIALS})


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
        if scope in ELEVATED_PROVIDER_SCOPES:
            raise ValueError(
                f"provider group {group!r} maps to the elevated scope {scope!r}. Elevated grants "
                f"are time-boxed, individually justified and separately audited (ADR-0013 §5a/§8) — "
                f"they are not granted by group membership."
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


#: Where :func:`require_elevated` records the class a route needs. Read by
#: :func:`upstream_bearer` and by the relay's retry decision, and set nowhere else.
STATE_ELEVATED_SCOPE = "elevated_scope"


def elevated_scope_wanted(request: Any) -> Optional[str]:
    """The elevated class this request declared it needs, or ``None``.

    ``None`` is the answer for every route that did not ask, which is what keeps the
    elevated credential off routine traffic. A route that *should* have asked and did not
    relays the ordinary token and is refused by the gateway — the safe direction, and a
    loud one.
    """
    return getattr(getattr(request, "state", None), STATE_ELEVATED_SCOPE, None)


def require_elevated(provider_scope: str):
    """Dependency for a route whose whole purpose is an elevated capability (§5a/§8/§11).

    Two jobs, and **neither is the authorization boundary** — the gateway verifies the grant
    claim on the token it is handed, and that check is deliberately not reproducible here
    (§11c: the side that chooses a value cannot be the side that authorizes it):

    * **Mark the request** so :func:`upstream_bearer` hands over the step-up token. Without
      a mark the elevated credential is never relayed at all.
    * **Refuse early** when a provider session holds no matching elevation, so an operator
      is told to elevate instead of collecting an opaque 401 from upstream — and so a
      single-use grant is not spent on a request that was going to fail anyway.

    Tenant-plane and password sessions pass straight through: they have no elevation to
    hold, and their authority on these routes is decided by the gateway and by the role gate
    beside this dependency respectively.
    """

    async def _dep(request: Request) -> None:
        setattr(request.state, STATE_ELEVATED_SCOPE, provider_scope)
        sess = await current_session(request)
        if session_plane(sess) != PLANE_PROVIDER:
            return
        from .grants import active_elevated_grant, active_grant

        now = time.time()
        act = active_grant(sess, now=now)
        held = active_elevated_grant(sess, tenant=act.tenant, now=now) if act is not None else None
        if held is None or held.provider_scope != provider_scope:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"This operation needs a live {provider_scope!r} elevation for this tenant. "
                    "Elevations are per-operation and step-up backed (ADR-0013 §8); acquire one "
                    "and retry."
                ),
            )

    return _dep


async def deny_password_session(request: Request) -> None:
    """Refuse the local break-glass login on routes that hand back credentials.

    Password sessions proxy with the stack's **admin** gateway token, which carries every
    `backup:*` scope. So on a backup route the BFF's role gate is not one control among
    several — it is the only one, and admitting `admin` there would produce a complete
    credential dump with no step-up, no elevation and nothing in either audit chain naming a
    grant. Break-glass exists to repair a broken fleet, not to export one.
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

    **A provider-plane session must never reach that fallback** (ADR-0013 §4/§5a). Returning
    ``None`` for one is not "no credential" — the ``GatewayClient`` carries the tenant
    stack's *admin* key as its default header, so a fall-through would present a provider
    operator to the tenant's gateway as gateway ``admin``: above the §5a ceiling that makes
    provider access everyday debugging, carrying `tools:call` and every `backup:*` with no
    step-up and no grant claim, and recorded in the tenant's audit as a shared key rather
    than a human. That is precisely the outcome the second-issuer design (§6) exists to
    replace, so it fails closed here rather than being avoided by convention upstream.
    """
    sess = await current_session(request)
    if session_plane(sess) == PLANE_PROVIDER:
        from .grants import active_elevated_grant, active_grant, spend_elevated_grant

        now = time.time()
        act = active_grant(sess, now=now)
        if act is not None:
            # **Only routes that asked for it get the elevated credential.** Handing it to
            # every relayed request while an elevation is live looks harmless — the step-up
            # token is a strict superset — but the gateway consumes a single-use grant on
            # *first validation of the token*, whatever route it was for. So one background
            # `GET /api/devices` between the elevation and the operation it was raised for
            # burns the grant on a device list, and the real call is refused. The mark is
            # set by `require_elevated`, which is the only thing that can set it.
            wanted = elevated_scope_wanted(request)
            elevated = active_elevated_grant(sess, tenant=act.tenant, now=now)
            # **One comparison carries both properties.** It has to match the class, because
            # an invoke elevation cannot pay for a credentials route — the two differ in
            # lifetime and single-use, so the wrong one is a different grant, not a narrower
            # one. And a route that never declared a class compares against `None`, which no
            # real grant equals, so the same test is what keeps the credential off routine
            # traffic. Written as two guards first; mutation testing showed each one masked
            # the other, so the defect this exists to prevent could return with every
            # mutation still killed. Neither was individually falsifiable. This is.
            if elevated is not None and elevated.provider_scope == wanted:
                # The step-up token carries the `mcp_grant` claim the gateway verifies, and
                # the gateway *unions* the granted scopes onto the principal's own — so this
                # token is a strict superset of the ordinary one and there is no per-route
                # choice to get wrong.
                #
                # Spending happens here, at the moment the credential is handed out, because
                # that is what the gateway's own consumption measures: it consumes on first
                # validation, so a second request bearing the same token is refused there.
                # Dropping it here keeps the BFF's audit honest about "one operation"
                # instead of leaving the bound entirely downstream.
                spent = spend_elevated_grant(sess)
                if spent is not None:
                    await _persist_session(request, sess)
                return elevated.access_token
        token = sess.get("access_token") if sess else None
        if not token:
            raise HTTPException(
                status_code=403,
                detail=(
                    "A provider session has no credential to present to this tenant's gateway. "
                    "It is never relayed with the stack's admin key (ADR-0013 §4/§5a)."
                ),
            )
        return token
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

    A provider-plane session reaches this plane **only while holding a live act-on-tenant
    grant naming the tenant this deployment serves** (ADR-0013 §4). Cross-tenant power is
    exercised, not held: the grant is a discrete, audited, time-boxed act, and everything
    about it — one tenant at a time, an absolute window, a justification — lives in
    `grants.py`.

    Three parts to the check, and all are load-bearing:

    * **`settings.tenant_id` must be configured.** Empty is the default and admits nobody,
      which is what keeps every existing tenant-stack deployment behaving exactly as it did
      — and it fails closed, since a deployment that cannot name itself cannot verify that
      a grant names *it*.
    * **The grant must name that tenant.** Without the comparison, "act on tenant X" is
      "act on any tenant", which is §4 inverted rather than implemented.
    * **The session must have a credential of its own to present.** The grant is the BFF's
      authorization to proceed; it is not a credential. Admitting a session with nothing to
      relay does not produce a refusal upstream — it produces a request carrying the stack's
      *admin* key, which is above the §5a ceiling and attributable to nobody. Checked at the
      gate so the refusal is one clean 403 here rather than a surprise mid-relay.
    """

    async def _dep(request: Request) -> SessionInfo:
        sess = await current_session(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if session_plane(sess) == PLANE_PROVIDER:
            from .grants import active_grant

            tenant_id = getattr(request.app.state.settings, "tenant_id", "") or ""
            grant = active_grant(sess, now=time.time())
            # Grant first, credential second — deliberately. "You have not authorized an act
            # on this tenant" is the condition an operator is actually in, and it is the one
            # they can fix; leading with the credential message would answer a question they
            # did not ask. Both refuse, so the order costs nothing but clarity.
            if not tenant_id or grant is None or grant.tenant != tenant_id:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "This is the tenant data plane; a provider session reaches it only while "
                        "holding a live 'act on tenant' grant for this tenant (ADR-0013 §4)."
                    ),
                )
            if not sess.get("access_token"):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "A provider session holds no credential for this tenant's gateway, so it "
                        "cannot reach the tenant data plane — and it is never relayed with the "
                        "stack's admin key (ADR-0013 §4/§5a)."
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
