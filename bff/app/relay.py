# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Relay to the gateway with silent OIDC access-token refresh (ADR-0007, review #4).

An OIDC access token is short-lived. Without refresh, the first call after it expires
401s and the SPA drops the user to the login screen mid-session. Here, when the gateway
rejects a relayed OIDC token, the BFF transparently exchanges the stored refresh token
for a new access token (server-side, never exposed to the browser) and retries the call
once. Password sessions carry no refresh token, so their 401s pass straight through.

Concurrency note: refresh state lives in the per-user signed cookie, not server memory,
so two in-flight requests racing an expiry may both refresh. With refresh-token rotation
that can briefly invalidate one token; the loser simply 401s and the user re-logs. A
server-side token store would be needed to fully serialise this — out of scope here.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from fastapi import Request

from .security import upstream_bearer


async def refresh_oidc_access_token(request: Request) -> Optional[str]:
    """Exchange the session's refresh token for a fresh access token, update the session,
    and return the new access token — or None when refresh is impossible/failed.

    Rotated refresh tokens and any re-issued id_token are persisted back to the session."""
    sess = request.session.get("auth")
    oidc = request.app.state.oidc
    if not (isinstance(sess, dict) and sess.get("kind") == "oidc" and sess.get("refresh_token") and oidc is not None):
        return None
    try:
        tokens = await oidc.refresh_tokens(refresh_token=sess["refresh_token"])
    except Exception:
        return None  # IdP unreachable / refresh rejected → caller keeps the original 401
    access = tokens.get("access_token")
    if not access:
        return None
    sess["access_token"] = access
    if tokens.get("refresh_token"):  # the IdP may rotate the refresh token
        sess["refresh_token"] = tokens["refresh_token"]
    if tokens.get("id_token"):
        sess["id_token"] = tokens["id_token"]
    request.session["auth"] = sess
    return access


async def relay_get(request: Request, path: str) -> httpx.Response:
    """GET the gateway, refreshing the OIDC token and retrying once on a 401."""
    gw = request.app.state.gateway
    resp = await gw.get(path, bearer=upstream_bearer(request))
    if resp.status_code == 401:
        refreshed = await refresh_oidc_access_token(request)
        if refreshed:
            resp = await gw.get(path, bearer=refreshed)
    return resp


async def relay_request(request: Request, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
    """Proxy a method to the gateway, refreshing the OIDC token and retrying once on a 401."""
    gw = request.app.state.gateway
    resp = await gw.request(method, path, json=json, bearer=upstream_bearer(request))
    if resp.status_code == 401:
        refreshed = await refresh_oidc_access_token(request)
        if refreshed:
            resp = await gw.request(method, path, json=json, bearer=refreshed)
    return resp
