# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Thin async client to the gateway API, carrying the admin bearer token.

Centralised so the credential is attached in exactly one place and never leaks to
the browser. Generated typed clients (from the gateway's /openapi.json) can replace
this later without changing the routers.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .config import Settings


class GatewayClient:
    def __init__(self, settings: Settings) -> None:
        headers = {}
        if settings.gateway_token:
            headers["Authorization"] = f"Bearer {settings.gateway_token}"
        # The gateway mounts its management API under a version prefix (default /v1).
        # Prepend it here, in one place, so routers stay version-agnostic and an
        # absolute httpx path can't accidentally bypass it.
        self._prefix = "/" + settings.gateway_api_prefix.strip("/") if settings.gateway_api_prefix.strip("/") else ""
        self._client = httpx.AsyncClient(
            base_url=settings.gateway_url,
            headers=headers,
            timeout=httpx.Timeout(10.0, read=30.0),
        )

    def _with_prefix(self, path: str) -> str:
        return f"{self._prefix}/{path.lstrip('/')}"

    @staticmethod
    def _auth(bearer: Optional[str]) -> Optional[dict]:
        # A per-request bearer (an OIDC user's access token) overrides the client's
        # default admin Authorization for that call only — the relay path (ADR-0007
        # Mode A). When None, httpx uses the client-level admin header.
        return {"Authorization": f"Bearer {bearer}"} if bearer else None

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        bearer: Optional[str] = None,
        headers: Optional[dict] = None,
    ) -> httpx.Response:
        """``headers`` carries transport headers the caller must set — the MCP session id on
        the tool-invocation path is the only current use. Merged *under* the auth header so
        a caller cannot substitute its own ``Authorization`` and bypass the bearer choice
        made in :func:`app.security.upstream_bearer`."""
        # Compared case-insensitively because HTTP header names are. Popping the two
        # obvious spellings left `authorization:` — and a dict carrying both spellings does
        # not overwrite, it produces two headers on the wire.
        merged = {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"}
        merged.update(self._auth(bearer) or {})
        return await self._client.request(method, self._with_prefix(path), json=json, headers=merged or None)

    async def get(self, path: str, *, bearer: Optional[str] = None) -> httpx.Response:
        return await self._client.get(self._with_prefix(path), headers=self._auth(bearer))

    async def aclose(self) -> None:
        await self._client.aclose()
