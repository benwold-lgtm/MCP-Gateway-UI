# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Relay to the gateway with silent OIDC access-token refresh (ADR-0007, review #4).

An OIDC access token is short-lived. Without refresh, the first call after it expires
401s and the SPA drops the user to the login screen mid-session. Here, when the gateway
rejects a relayed OIDC token, the BFF transparently exchanges the stored refresh token
for a new access token (server-side, never exposed to the browser) and retries the call
once. Password sessions carry no refresh token, so their 401s pass straight through.

Concurrency: refresh runs under the session store's per-session lock, so two in-flight
requests racing an expiry refresh exactly once — the second finds the first's rotated
tokens already persisted and reuses them. This closes the rotation race the old
cookie-based session (no shared server state) had to document as unfixable.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from fastapi import HTTPException, Request

from . import sessions
from .gateway_pool import TenantUnreachable
from .security import PLANE_PROVIDER, _persist_session, current_session, session_plane, upstream_bearer


async def refresh_oidc_access_token(request: Request) -> Optional[str]:
    """Exchange the session's refresh token for a fresh access token, update the stored
    session, and return the new access token — or None when refresh is impossible/failed.

    Rotated refresh tokens and any re-issued id_token are persisted back to the store."""
    sess = await sessions.load(request)
    oidc = request.app.state.oidc
    if not (isinstance(sess, dict) and sess.get("kind") == "oidc" and sess.get("refresh_token") and oidc is not None):
        return None
    store = request.app.state.sessions
    sid = sessions.current_sid(request)
    if not sid:
        return None
    async with store.lock(sid):
        current = await store.get(sid)
        if not (isinstance(current, dict) and current.get("refresh_token")):
            return None  # session ended while we waited for the lock
        if current.get("access_token") != sess.get("access_token"):
            # A concurrent request already refreshed while we held back — reuse its
            # result instead of burning (and with rotation, invalidating) the token.
            sessions.cache(request, current)
            return current.get("access_token")
        try:
            tokens = await oidc.refresh_tokens(refresh_token=current["refresh_token"])
        except Exception:
            return None  # IdP unreachable / refresh rejected → caller keeps the original 401
        access = tokens.get("access_token")
        if not access:
            return None
        current["access_token"] = access
        if tokens.get("refresh_token"):  # the IdP may rotate the refresh token
            current["refresh_token"] = tokens["refresh_token"]
        if tokens.get("id_token"):
            current["id_token"] = tokens["id_token"]
        await store.set(sid, current)
        sessions.cache(request, current)
        return access


async def _drop_dead_support_grant(request: Request) -> None:
    """A provider session's delegated support grant just 401'd (ADR-0017 §7) — the gateway
    checks it live on every request, so a refusal here means it is genuinely gone (revoked
    or expired), not a caching problem this side needs to paper over. Clearing it is what
    makes the *next* poll/read honestly report "no grant" instead of a phantom stale one;
    there is nothing to refresh, unlike the OIDC case above."""
    sess = await sessions.load(request)
    if not (
        isinstance(sess, dict) and session_plane(sess) == PLANE_PROVIDER and isinstance(sess.get("support_grant"), dict)
    ):
        return
    sess.pop("support_grant", None)
    await _persist_session(request, sess)


async def _gateway_for(request: Request):
    """Which `GatewayClient` a relay should use for this request.

    A tenant or password session always uses this process's own configured gateway — the
    one fixed target a tenant-stack BFF has always had. A provider session holding a
    delegated support grant (ADR-0017 §7) instead resolves to *that tenant's* gateway from
    the pool (ADR-0021, scoped): `app.state.gateway` on a provider deployment names no
    tenant in particular, so sending a tenant-scoped credential to it would reach the wrong
    backend outright, not merely an inconvenient one.

    By the time this runs, `require_role`/`upstream_bearer` have already confirmed a
    provider session holds *some* credential, so the only failures possible here are
    inconsistencies (a grant with no recorded tenant, or naming one the registry no longer
    has) — both fail closed with a 500 rather than silently falling back to the ambiguous
    single-gateway default.
    """
    sess = await current_session(request)
    if session_plane(sess) != PLANE_PROVIDER:
        return request.app.state.gateway
    grant = (sess or {}).get("support_grant")
    tenant_id = grant.get("tenant_id") if isinstance(grant, dict) else None
    if not tenant_id:
        raise HTTPException(
            status_code=500,
            detail="This provider session's support grant has no recorded tenant to relay to.",
        )
    try:
        return await request.app.state.gateway_pool.get(tenant_id)
    except KeyError:
        raise HTTPException(
            status_code=500,
            detail=f"This provider session's support grant names a tenant the registry no longer has: {tenant_id!r}.",
        ) from None
    except TenantUnreachable as exc:
        # Distinct from the KeyError above on purpose: the tenant IS known, and the relay
        # cannot proceed because its credential could not be fetched. A 503 says the estate is
        # intact and something upstream is down, where the 500 above says the grant points at
        # a tenant that no longer exists.
        raise HTTPException(status_code=503, detail=str(exc)) from None


async def relay_get(request: Request, path: str) -> httpx.Response:
    """GET the gateway, refreshing the OIDC token and retrying once on a 401."""
    gw = await _gateway_for(request)
    resp = await gw.get(path, bearer=await upstream_bearer(request))
    if resp.status_code == 401:
        refreshed = await refresh_oidc_access_token(request)
        if refreshed:
            resp = await gw.get(path, bearer=refreshed)
        else:
            await _drop_dead_support_grant(request)
    return resp


async def relay_request(
    request: Request,
    method: str,
    path: str,
    *,
    json: Optional[Any] = None,
    headers: Optional[dict] = None,
) -> httpx.Response:
    """Proxy a method to the gateway, refreshing the OIDC token and retrying once on a 401."""
    gw = await _gateway_for(request)
    resp = await gw.request(method, path, json=json, bearer=await upstream_bearer(request), headers=headers)
    if resp.status_code == 401:
        refreshed = await refresh_oidc_access_token(request)
        if refreshed:
            resp = await gw.request(method, path, json=json, bearer=refreshed, headers=headers)
        else:
            await _drop_dead_support_grant(request)
    return resp
