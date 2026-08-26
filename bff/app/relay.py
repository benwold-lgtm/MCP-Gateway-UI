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
from fastapi import Request

from . import sessions
from .security import upstream_bearer


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


async def relay_get(request: Request, path: str) -> httpx.Response:
    """GET the gateway, refreshing the OIDC token and retrying once on a 401."""
    gw = request.app.state.gateway
    resp = await gw.get(path, bearer=await upstream_bearer(request))
    if resp.status_code == 401:
        refreshed = await refresh_oidc_access_token(request)
        if refreshed:
            resp = await gw.get(path, bearer=refreshed)
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
    gw = request.app.state.gateway
    resp = await gw.request(method, path, json=json, bearer=await upstream_bearer(request), headers=headers)
    if resp.status_code == 401:
        refreshed = await refresh_oidc_access_token(request)
        if refreshed:
            resp = await gw.request(method, path, json=json, bearer=refreshed, headers=headers)
    return resp
