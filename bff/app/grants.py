# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Act-on-tenant: cross-tenant power exercised, not held (ADR-0013 §4/§8).

A provider session does not carry ambient authority over every tenant for eight hours.
Reaching a tenant's data plane is a **discrete, audited, time-boxed act on one named
tenant** — and the three rules in §8 are what stop that sentence being decorative:

1. **One tenant at a time.** A session holds act-on-tenant for exactly one tenant;
   acquiring another drops the first. The natural store for "which tenants may I act on"
   is a dict keyed by tenant, and that is §4 defeated by accumulation — hold three grants
   and you have estate-wide authority assembled one justified act at a time. This module
   stores **one grant, under one key**, so the shape itself refuses the accumulation.
2. **Renewal is a new act, not an extension.** :func:`authorize_act_on_tenant` always
   mints: new id, new justification, new deadline, and the caller writes a new audit
   record. Finding the live grant and pushing its expiry out is a sliding window with
   extra steps, and a sliding window never expires for someone who keeps working.
3. **The window is absolute.** :func:`active_grant` is a pure read — it never writes back,
   never refreshes, and takes ``now`` as an argument so the clock is testable.

Two more that the ADR implies rather than states:

- **The deadline is stamped at mint time**, never recomputed from the configured lifetime.
  Recomputing means raising the config reaches backwards and extends grants already issued.
- **The justification is enforced.** §8 says *assert the tenant and a justification*, and a
  field that accepts an empty string is decoration. It is the only record of **why** a
  customer's stack was touched, which is the question an audit is actually asked.

Deliberately *not* here: what the BFF then presents to a tenant gateway. This grant opens
the BFF's own gate. Reaching N gateways is slice 3, and the two elevated grants
(`provider:invoke`, `provider:credentials`) are separate acts behind a step-up (§5a/§8).
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional

from .security import (
    PLANE_PROVIDER,
    SCOPE_PROVIDER_ADMIN,
    SCOPE_PROVIDER_CREDENTIALS,
    SCOPE_PROVIDER_INVOKE,
)

#: Where the elevated grant lives. Singular for the same reason act-on-tenant is: one act,
#: one elevation on top of it.
SESSION_KEY_ELEVATED = "elevated_grant"

#: Where the single grant lives on the session. Singular, and not keyed by tenant — see
#: rule 1 above. A test pins the name, because the plural is the shape that permits
#: accumulation and would otherwise arrive as an innocuous refactor.
SESSION_KEY = "act_on_tenant"

#: §8's window for the everyday motion. A duration is configuration; the *relationship* —
#: longer than either elevated grant, because this is the one that must not train reflexive
#: approval — is the decision.
DEFAULT_ACT_ON_TENANT_SECONDS = 3600

#: A justification lands in a hash-chained, append-only audit record, so it is unbounded
#: operator input reaching a structure nothing can later edit.
MAX_JUSTIFICATION = 2000

#: Conservative tenant shape. The tenant is a *discriminator* — compared against this
#: deployment's own identity to decide whether a request proceeds — so odd shapes are
#: refused at the door and the comparison stays about identity rather than normalisation.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$", re.IGNORECASE)


class GrantError(Exception):
    """An act-on-tenant grant was requested but cannot be issued. Routes turn this into a
    4xx naming the reason: an operator who is refused should learn *which* rule refused
    them, since the alternative is a retry loop against an invisible constraint."""


@dataclass(frozen=True)
class ActOnTenant:
    """One act. ``expires_at`` is absolute and is never moved after minting."""

    id: str
    tenant: str
    justification: str
    granted_at: float
    expires_at: float

    def as_dict(self) -> dict[str, Any]:
        """The session representation. Plain JSON types only: the session store is Redis in
        every deployment that matters, and a dataclass on the session works perfectly
        against the in-memory store and fails only in production."""
        return {
            "id": self.id,
            "tenant": self.tenant,
            "justification": self.justification,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_session(cls, session: Any) -> Optional["ActOnTenant"]:
        """Revive the stored grant, or ``None`` if there isn't a well-formed one.

        Fails closed on junk rather than raising. A grant is a plain dict in a shared store,
        so a missing or wrong-typed field must read as *no authority* — raising would turn
        a corrupted session into a 500, which is an outage where a re-authorization would
        do.
        """
        raw = (session or {}).get(SESSION_KEY) if isinstance(session, dict) else None
        if not isinstance(raw, dict):
            return None
        gid, tenant, why = raw.get("id"), raw.get("tenant"), raw.get("justification")
        granted, expires = raw.get("granted_at"), raw.get("expires_at")
        if not (isinstance(gid, str) and gid and isinstance(tenant, str) and tenant):
            return None
        if not isinstance(why, str):
            return None
        if not _is_number(granted) or not _is_number(expires):
            return None
        return cls(
            id=gid,
            tenant=tenant,
            justification=why,
            granted_at=float(granted),
            expires_at=float(expires),
        )


def _is_number(value: Any) -> bool:
    # `bool` is an `int`, and a grant whose deadline is `True` should not become 1.0.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_tenant(tenant: Any) -> str:
    if not isinstance(tenant, str) or not _TENANT_RE.match(tenant.strip()):
        raise GrantError(
            f"{tenant!r} is not a usable tenant name: a grant names exactly one tenant, and that "
            f"name is compared against this deployment's own identity (ADR-0013 §4)"
        )
    return tenant.strip()


def _check_justification(justification: Any) -> str:
    text = justification.strip() if isinstance(justification, str) else ""
    if not text:
        raise GrantError(
            "an act-on-tenant grant requires a justification (ADR-0013 §8) — it is the only "
            "record of why a customer's stack was touched"
        )
    if len(text) > MAX_JUSTIFICATION:
        # Refused, not truncated. A justification the operator wrote and the record does
        # not contain is worse than no record, because it reads as complete.
        raise GrantError(f"justification is too long ({len(text)} > {MAX_JUSTIFICATION} characters)")
    return text


def authorize_act_on_tenant(
    session: dict[str, Any],
    *,
    tenant: Any,
    justification: Any,
    now: float,
    lifetime: int = DEFAULT_ACT_ON_TENANT_SECONDS,
) -> ActOnTenant:
    """Mint a grant onto ``session``, replacing whatever it held.

    **Always mints.** There is no "already holds one, extend it" branch, deliberately —
    that branch is §8 rule 2 inverted, and its absence is why re-authorizing produces a new
    id, a new justification and a new audit record.
    """
    if (session or {}).get("plane") != PLANE_PROVIDER:
        # The write half of the plane wall. §3 fixes the plane at login so this should be
        # unreachable, but a shared session store is the topology where a session from one
        # population meets a process serving the other.
        raise GrantError("act-on-tenant is a provider-plane act; this is not a provider-plane session")
    if SCOPE_PROVIDER_ADMIN not in set(session.get("provider_scopes") or []):
        # §7: `provider:monitor` is the estate-health scope and holds no tenant API access
        # at all, so it must not mint the grant that produces some.
        raise GrantError(
            f"minting an act-on-tenant grant requires {SCOPE_PROVIDER_ADMIN!r}; this session holds "
            f"{sorted(session.get('provider_scopes') or [])}"
        )
    if not isinstance(lifetime, int) or isinstance(lifetime, bool) or lifetime <= 0:
        raise GrantError(f"act-on-tenant lifetime must be a positive number of seconds, got {lifetime!r}")

    grant = ActOnTenant(
        id=f"aot-{secrets.token_urlsafe(9)}",
        tenant=_check_tenant(tenant),
        justification=_check_justification(justification),
        granted_at=float(now),
        # Stamped once, here. Nothing downstream recomputes it, so raising the configured
        # lifetime cannot reach backwards into grants already issued.
        expires_at=float(now) + lifetime,
    )
    session[SESSION_KEY] = grant.as_dict()
    # A new act is a new act, so it never inherits the previous one's elevation — including
    # when the tenant is unchanged. Carrying it over would make "renewal is a new act" hold
    # for the act and quietly fail for the more dangerous thing riding on top of it, and
    # across a tenant *switch* it would let a `tools:call` grant obtained for one customer
    # be spent on another.
    session.pop(SESSION_KEY_ELEVATED, None)
    return grant


def active_grant(session: Any, *, now: float) -> Optional[ActOnTenant]:
    """The session's live grant, or ``None``. A **pure read**: never writes back, never
    refreshes a deadline. §8's window is absolute, and the read path is where "refresh on
    access" looks like hygiene and is the whole bug."""
    if not isinstance(session, dict) or session.get("plane") != PLANE_PROVIDER:
        # The read half of the plane wall, checked before the grant is even parsed: a grant
        # forged onto a tenant session must confer nothing.
        return None
    grant = ActOnTenant.from_session(session)
    if grant is None or grant.expires_at <= now:
        return None
    return grant


def release_act_on_tenant(session: dict[str, Any]) -> Optional[ActOnTenant]:
    """Drop the grant, returning what was held (or ``None``). Idempotent.

    Returns the *stored* grant rather than only a live one, so a caller auditing the drop
    names what actually ended even when it had already expired.
    """
    held = ActOnTenant.from_session(session)
    if isinstance(session, dict):
        session.pop(SESSION_KEY, None)
        # The elevation cannot outlive the act it was layered on.
        session.pop(SESSION_KEY_ELEVATED, None)
    return held


# --- the two elevated grants (ADR-0013 §5a/§8/§11b) ---------------------------
#
# Layered on top of an act, never instead of one: `provider:admin` plus a live
# act-on-tenant grant is the floor, and the elevation adds one bounded capability above it
# for one tenant. §5a's carve-out is what makes provider access everyday debugging, so
# these two are the points where a compromised provider session converts into real damage —
# actuating a customer's hardware, or walking off with their credentials — and they are the
# only places §8 spends a step-up.


@dataclass(frozen=True)
class ElevatedSpec:
    """One §8 class. Durations are configuration; the relationships are the decision."""

    #: What goes to the gateway. **Gateway** scopes, never provider ones: `provider:invoke`
    #: is a BFF concept and the gateway has never heard of it (§11). This mapping is the
    #: line, and it is drawn here because this is the side that does the translating — a
    #: leak would not be *refused* downstream, it would be silently ignored.
    gateway_scopes: tuple[str, ...]
    max_lifetime: int
    single_use: bool


ELEVATED_GRANT_SPECS: dict[str, ElevatedSpec] = {
    # A short absolute window rather than one call: §8's grant gates *initiation*, and one
    # debugging session is several calls. Matches the gateway's own 900s for `tools:call`.
    SCOPE_PROVIDER_INVOKE: ElevatedSpec(gateway_scopes=("tools:call",), max_lifetime=900, single_use=False),
    # Single use — one operation. The window is a backstop under that, and deliberately no
    # looser than the invoke one. For the provider, who holds MCP_SECRET_KEY, a ciphertext
    # archive is a credential dump too (§5b), so all three backup scopes are treated alike.
    SCOPE_PROVIDER_CREDENTIALS: ElevatedSpec(
        gateway_scopes=("backup:read", "backup:write", "backup:export-portable"),
        max_lifetime=300,
        single_use=True,
    ),
}


#: Provider scope → the short class name a scope template interpolates. Explicit rather
#: than derived by stripping ``provider:``, because the value ends up in an IdP's registered
#: scope names: it is an external contract, and it should change only on purpose.
GRANT_CLASS_NAMES: dict[str, str] = {
    SCOPE_PROVIDER_INVOKE: "invoke",
    SCOPE_PROVIDER_CREDENTIALS: "credentials",
}


def step_up_scopes(template: str, *, tenant: str, provider_scope: str) -> tuple[str, ...]:
    """Build the scopes that tell the IdP *which* grant to mint (ADR-0013 §11c).

    §11b assumed the IdP could mint a grant from a request that named neither the tenant nor
    the class. Measurement against real IdPs killed that: a scope is the only carrier that
    survives to issuance, so the request has to say it out loud.

    The template is deployment config because scope names are registered in someone else's
    IdP. Splitting the result on whitespace lets one setting express either factoring — one
    scope per tenant plus one per class, or a single combined scope — without this code
    having an opinion about which.

    Note what this does **not** do: it does not authorize anything. The scope selects, and
    an IdP grants a registered scope to whoever asks. The gateway intersects the resulting
    tenant against the operator's directory entitlement, and that is the actual bound (§11c).
    """
    if not template:
        raise GrantError(
            "no step-up scope template is configured, so the authorization request cannot "
            "tell the IdP which grant to mint and would come back with no grant claim "
            "(ADR-0013 §11c)"
        )
    if not isinstance(tenant, str) or not _TENANT_RE.match(tenant):
        # Interpolating into a space-delimited scope string: a tenant carrying whitespace
        # would inject an additional scope. `_TENANT_RE` already forbids it, and this
        # re-check keeps that guarantee local to the place that depends on it rather than
        # inherited from a caller that might change.
        raise GrantError(f"tenant {tenant!r} is not a usable tenant id")
    grant_class = GRANT_CLASS_NAMES.get(provider_scope)
    if grant_class is None:
        raise GrantError(f"{provider_scope!r} is not an elevated grant class")
    try:
        rendered = template.format(tenant=tenant, grant_class=grant_class)
    except (KeyError, IndexError) as exc:
        raise GrantError(
            f"the step-up scope template names {exc} — only {{tenant}} and {{grant_class}} " f"are available"
        ) from None
    scopes = tuple(rendered.split())
    if not scopes:
        raise GrantError("the step-up scope template rendered to nothing")
    return scopes


@dataclass(frozen=True)
class ElevatedGrant:
    """A verified step-up, and the token it produced.

    The token lives **inside** the grant rather than beside it: the step-up token *is* the
    capability, so making the record that holds it the same record that expires means there
    is no second place to remember to clear. Dropping the grant drops the credential.
    """

    id: str
    tenant: str
    provider_scope: str
    gateway_scopes: tuple[str, ...]
    justification: str
    granted_at: float
    expires_at: float
    single_use: bool
    access_token: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tenant": self.tenant,
            "provider_scope": self.provider_scope,
            "gateway_scopes": list(self.gateway_scopes),
            "justification": self.justification,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "single_use": self.single_use,
            "access_token": self.access_token,
        }

    @classmethod
    def from_session(cls, session: Any) -> Optional["ElevatedGrant"]:
        raw = (session or {}).get(SESSION_KEY_ELEVATED) if isinstance(session, dict) else None
        if not isinstance(raw, dict):
            return None
        gid, tenant = raw.get("id"), raw.get("tenant")
        scope, gscopes = raw.get("provider_scope"), raw.get("gateway_scopes")
        why, token = raw.get("justification"), raw.get("access_token")
        granted, expires = raw.get("granted_at"), raw.get("expires_at")
        if not (isinstance(gid, str) and gid and isinstance(tenant, str) and tenant):
            return None
        if scope not in ELEVATED_GRANT_SPECS:
            return None
        if not isinstance(gscopes, list) or not gscopes or not all(isinstance(x, str) for x in gscopes):
            return None
        if not isinstance(why, str) or not isinstance(token, str) or not token:
            # An elevation with no token is not a weaker elevation, it is a record with no
            # capability — and treating it as live would send the *ordinary* operator token
            # to a route the caller believes is elevated.
            return None
        if not _is_number(granted) or not _is_number(expires):
            return None
        return cls(
            id=gid,
            tenant=tenant,
            provider_scope=scope,
            gateway_scopes=tuple(gscopes),
            justification=why,
            granted_at=float(granted),
            expires_at=float(expires),
            single_use=bool(raw.get("single_use")),
            access_token=token,
        )


def elevated_spec(provider_scope: Any) -> ElevatedSpec:
    """The §8 class for a BFF scope, or :class:`GrantError`.

    A closed range. `provider:admin` needs no elevation and `provider:monitor` has no tenant
    access at all, so asking to elevate either is a misunderstanding of the model rather
    than a narrower request — and it fails loudly instead of minting something meaningless.
    """
    spec = ELEVATED_GRANT_SPECS.get(provider_scope) if isinstance(provider_scope, str) else None
    if spec is None:
        raise GrantError(
            f"{provider_scope!r} is not an elevatable scope. Only {sorted(ELEVATED_GRANT_SPECS)} are "
            f"elevated grants (ADR-0013 §5a/§8); everything else is either held by group membership "
            f"or not a provider scope at all."
        )
    return spec


def _check_claim(claim: Any, *, tenant: str, spec: ElevatedSpec) -> str:
    """Check the IdP-minted claim is the grant that was asked for, and return its id.

    The gateway verifies its own copy and is authoritative (§11b). This is not that check
    repeated — it is the BFF confirming that what came back matches what it requested,
    *before* it writes an audit record saying so. A record asserting a step-up the writer
    never confirmed is worse than no record.

    §11c sharpens what this is *not*. The tenant here was chosen by this process, so the
    comparison is a round-trip check — "the IdP answered the question I asked" — and it
    establishes no authority whatsoever. What makes the tenant legitimate is the gateway
    intersecting it against the operator's directory entitlement, which is deliberately on
    the other side of the wire: this side picked the value, and a check by the side that
    picked it proves only that it did not change its mind.
    """
    if not isinstance(claim, dict):
        raise GrantError("the step-up produced no usable grant claim")
    gid = claim.get("id")
    if not isinstance(gid, str) or not gid:
        raise GrantError("the grant claim has no usable 'id' — nothing to audit or consume against")
    if claim.get("tenant") != tenant:
        raise GrantError(f"the grant claim names tenant {claim.get('tenant')!r}, but this act is on {tenant!r}")
    scopes = claim.get("scopes")
    if not isinstance(scopes, list) or set(scopes) != set(spec.gateway_scopes):
        # Refused rather than intersected. Being handed a *different* grant than the one
        # requested is not a narrower grant, and quietly proceeding with it would make the
        # audit record describe an act that did not happen.
        raise GrantError(
            f"the grant claim carries scopes {scopes!r}, but this elevation requested " f"{list(spec.gateway_scopes)!r}"
        )
    return gid


def record_elevated_grant(
    session: dict[str, Any],
    *,
    tenant: Any,
    provider_scope: Any,
    justification: Any,
    claim: Any,
    access_token: Any,
    auth_time: Any,
    now: float,
) -> ElevatedGrant:
    """Record a verified step-up as an elevated grant on ``session``.

    Called only after the caller has checked the issued token's ``acr`` — that check lives
    at the callback because it is about the token, not about this record. Everything that
    is about *this act* is here.
    """
    spec = elevated_spec(provider_scope)
    tenant = _check_tenant(tenant)
    why = _check_justification(justification)

    act = active_grant(session, now=now)
    if act is None or act.tenant != tenant:
        # §4/§8: an elevation rides on an act. Without this it routes around
        # act-on-tenant's justification, its one-tenant-at-a-time rule and its audit trail
        # — §4 bypassed by the very mechanism §8 layers on top of it.
        raise GrantError(
            f"an elevated grant requires a live act-on-tenant grant for {tenant!r}; "
            f"authorize the act first (ADR-0013 §4/§8)"
        )

    if not _is_number(auth_time):
        raise GrantError("the token carries no usable auth_time, so the step-up cannot be dated")
    if float(auth_time) > now:
        # Otherwise the freshness check below is defeated from the same place it is enforced.
        raise GrantError("the token's auth_time is in the future")

    # One mechanism for two requirements: the window runs from the step-up, so a 15-minute
    # elevation *is* a 15-minute step-up freshness requirement. Two separate rules would
    # drift apart; the gateway makes the same choice on its side.
    deadline = float(auth_time) + spec.max_lifetime
    if deadline <= now:
        raise GrantError(
            f"the step-up is stale: its auth_time is more than {spec.max_lifetime}s old, so it "
            f"does not satisfy a step-up now (ADR-0013 §8)"
        )

    gid = _check_claim(claim, tenant=tenant, spec=spec)
    claim_exp = claim.get("exp")
    if _is_number(claim_exp) and float(claim_exp) < deadline:
        # The claim may bring the deadline in — an IdP with a tighter policy is honoured —
        # but never push it out. The window is computed here, from our clock.
        deadline = float(claim_exp)
    if deadline <= now:
        # Refused rather than stored. Capping can pull the deadline into the past, and a
        # grant that is dead on arrival is worse than a refusal: the operator has just
        # completed an MFA prompt, and would be told it succeeded before every subsequent
        # request quietly used their ordinary token instead.
        raise GrantError(
            f"the grant claim expires at {float(claim_exp):.0f}, which is already past — "
            f"the elevation would be dead on arrival"
        )

    if not isinstance(access_token, str) or not access_token:
        raise GrantError("the step-up produced no access token, so there is nothing to present upstream")

    grant = ElevatedGrant(
        id=gid,
        tenant=tenant,
        provider_scope=provider_scope,
        gateway_scopes=spec.gateway_scopes,
        justification=why,
        granted_at=float(now),
        expires_at=deadline,
        single_use=spec.single_use,
        access_token=access_token,
    )
    session[SESSION_KEY_ELEVATED] = grant.as_dict()
    return grant


def active_elevated_grant(session: Any, *, tenant: str, now: float) -> Optional[ElevatedGrant]:
    """The live elevation for ``tenant``, or ``None``. A pure read, like
    :func:`active_grant` and for the same reason.

    ``tenant`` is required rather than optional: an elevation is authority over one
    customer's hardware, and a caller that did not have to name which tenant it was asking
    about is a caller that can be handed the wrong one.
    """
    if not isinstance(session, dict) or session.get("plane") != PLANE_PROVIDER:
        return None
    grant = ElevatedGrant.from_session(session)
    if grant is None or grant.tenant != tenant or grant.expires_at <= now:
        return None
    return grant


def spend_elevated_grant(session: dict[str, Any]) -> Optional[ElevatedGrant]:
    """Consume one operation's worth of elevation.

    Drops a **single-use** grant and leaves an invoke-class one alone — §8's grant gates
    initiation, not completion, so one debugging session is several calls inside one
    window. Returns what was spent, for the caller's audit.
    """
    grant = ElevatedGrant.from_session(session)
    if grant is not None and grant.single_use:
        session.pop(SESSION_KEY_ELEVATED, None)
        return grant
    return None


def drop_elevated_grant(session: dict[str, Any]) -> Optional[ElevatedGrant]:
    """End any elevation. Returns what was held, so the caller can audit the drop."""
    held = ElevatedGrant.from_session(session)
    if isinstance(session, dict):
        session.pop(SESSION_KEY_ELEVATED, None)
    return held
