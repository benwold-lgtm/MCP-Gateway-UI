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

from .security import PLANE_PROVIDER, SCOPE_PROVIDER_ADMIN

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
    return held
