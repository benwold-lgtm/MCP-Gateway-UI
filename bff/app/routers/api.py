# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Browser-facing API: proxies to the gateway (and, later, Prometheus/Loki).

Every route is session-gated. Reads need any authenticated session; mutations need
an admin session. The browser never sees the gateway token — the GatewayClient
attaches it server-side.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..security import require_role

router = APIRouter(prefix="/api", tags=["api"])

_any = Depends(require_role())  # any authenticated session
_admin = Depends(require_role("admin"))


def _passthrough(resp: httpx.Response) -> JSONResponse:
    try:
        body: Any = resp.json()
    except ValueError:
        body = {"detail": resp.text}
    return JSONResponse(status_code=resp.status_code, content=body)


# --- Devices (proxied to the gateway) ----------------------------------------


@router.get("/overview", dependencies=[_any])
async def overview(request: Request) -> JSONResponse:
    # One upstream call — the gateway's F14 aggregate endpoint.
    return _passthrough(await request.app.state.gateway.get("/admin/overview"))


@router.get("/devices", dependencies=[_any])
async def list_devices(request: Request) -> JSONResponse:
    return _passthrough(await request.app.state.gateway.get("/devices"))


@router.get("/devices/{hostname}", dependencies=[_any])
async def get_device(hostname: str, request: Request) -> JSONResponse:
    return _passthrough(await request.app.state.gateway.get(f"/devices/{hostname}"))


@router.post("/devices", dependencies=[_admin])
async def register_device(request: Request) -> JSONResponse:
    body = await request.json()
    return _passthrough(await request.app.state.gateway.request("POST", "/devices", json=body))


@router.delete("/devices/{hostname}", dependencies=[_admin])
async def delete_device(hostname: str, request: Request) -> JSONResponse:
    return _passthrough(await request.app.state.gateway.request("DELETE", f"/devices/{hostname}"))


# --- Monitoring (Prometheus / Loki) — wired as stubs to fill in -------------


@router.get("/metrics/summary", dependencies=[_any])
async def metrics_summary(request: Request) -> JSONResponse:
    return _passthrough(await request.app.state.gateway.get("/metrics/summary"))


@router.get("/prometheus/query", dependencies=[_any])
async def prometheus_query(query: str, request: Request) -> JSONResponse:
    # TODO(phase 2): proxy to PROMETHEUS_URL/api/v1/query?query=... and render in
    # Grafana-style panels. Returns 501 until PROMETHEUS_URL is configured.
    settings = request.app.state.settings
    if not settings.prometheus_url:
        return JSONResponse(status_code=501, content={"detail": "PROMETHEUS_URL not configured"})
    async with httpx.AsyncClient(base_url=settings.prometheus_url, timeout=10.0) as client:
        return _passthrough(await client.get("/api/v1/query", params={"query": query}))


@router.get("/logs", dependencies=[_any])
async def logs(request: Request) -> JSONResponse:
    # TODO(phase 2): proxy a LogQL/Splunk query to LOKI_URL. The UI reads logs from
    # the log store directly via the BFF — the gateway is never in the log path.
    settings = request.app.state.settings
    if not settings.loki_url:
        return JSONResponse(status_code=501, content={"detail": "LOKI_URL not configured"})
    return JSONResponse(status_code=501, content={"detail": "log query not implemented in the starter scaffold"})
