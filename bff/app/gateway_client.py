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
        self._client = httpx.AsyncClient(
            base_url=settings.gateway_url,
            headers=headers,
            timeout=httpx.Timeout(10.0, read=30.0),
        )

    async def request(self, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
        return await self._client.request(method, path, json=json)

    async def get(self, path: str) -> httpx.Response:
        return await self._client.get(path)

    async def aclose(self) -> None:
        await self._client.aclose()
