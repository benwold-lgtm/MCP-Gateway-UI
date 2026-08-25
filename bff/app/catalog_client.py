# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Thin async client to the catalog service (ADR-0020), carrying its bearer token.

Mirrors `gateway_client.py`'s shape — one long-lived `httpx.AsyncClient`, the credential
attached in exactly one place — but unlike the gateway there is no per-request bearer to
swap in: this service has exactly one caller (this BFF) and one shared token (`auth.py` on
the catalog service side).

ADR-0020 §7: the catalog's unavailability must be a **named condition**, never inferred from
an empty list — a provider console showing no device types because the catalog is down must
not look like a provider who has curated none. `CatalogUnavailable` is what lets a route tell
the two apart; see `routers/catalog.py`.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .config import Settings


class CatalogUnavailable(Exception):
    """The catalog service is unreachable, or this BFF has no token configured for it."""


class CatalogClient:
    def __init__(self, settings: Settings) -> None:
        self._configured = bool(settings.catalog_service_url and settings.catalog_api_token)
        headers = {}
        if settings.catalog_api_token:
            headers["Authorization"] = f"Bearer {settings.catalog_api_token}"
        self._client = httpx.AsyncClient(
            base_url=settings.catalog_service_url or "http://catalog-not-configured.invalid",
            headers=headers,
            timeout=httpx.Timeout(10.0, read=30.0),
        )

    async def request(self, method: str, path: str, *, json: Optional[Any] = None) -> httpx.Response:
        if not self._configured:
            raise CatalogUnavailable("CATALOG_SERVICE_URL / CATALOG_API_TOKEN not configured on this BFF")
        try:
            return await self._client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            raise CatalogUnavailable(str(exc)) from exc

    async def aclose(self) -> None:
        await self._client.aclose()
