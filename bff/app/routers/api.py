# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Browser-facing API: proxies to the gateway (and, later, Prometheus/Loki).

Every route is session-gated. Reads need any authenticated session; mutations need
an admin session. The browser never sees the gateway token — the GatewayClient
attaches it server-side.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..relay import relay_get, relay_request
from ..security import require_role

router = APIRouter(prefix="/api", tags=["api"])

_any = Depends(require_role())  # any authenticated session
_admin = Depends(require_role("admin"))

# Upper bound on the recent-logs panel page size. The panel shows a tail, not a bulk
# export, so cap the caller-supplied limit to keep one request from pulling an unbounded
# result set out of Loki (the query itself is already confined to the configured backend).
_MAX_LOG_LIMIT = 1000


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
    return _passthrough(await relay_get(request, "/admin/overview"))


@router.get("/devices", dependencies=[_any])
async def list_devices(request: Request) -> JSONResponse:
    return _passthrough(await relay_get(request, "/devices"))


@router.get("/devices/{hostname}", dependencies=[_any])
async def get_device(hostname: str, request: Request) -> JSONResponse:
    return _passthrough(await relay_get(request, f"/devices/{hostname}"))


@router.get("/devices/{hostname}/diagnostics", dependencies=[_any])
async def device_diagnostics(hostname: str, request: Request) -> JSONResponse:
    # "Why is my device down?" — registry status, last-check age, spec/manifest
    # state, spawn error, and circuit breaker (gateway F-52).
    return _passthrough(await relay_get(request, f"/devices/{hostname}/diagnostics"))


@router.get("/devices/{hostname}/tools", dependencies=[_any])
async def device_tools(hostname: str, request: Request) -> JSONResponse:
    return _passthrough(await relay_get(request, f"/devices/{hostname}/tools"))


@router.get("/devices/{hostname}/tools/diff", dependencies=[_any])
async def device_tools_diff(hostname: str, request: Request) -> JSONResponse:
    # The device's most recent tool-set change (added/removed/changed + breaking),
    # for the "recent changes" panel (gateway F-41).
    return _passthrough(await relay_get(request, f"/devices/{hostname}/tools/diff"))


@router.post("/devices", dependencies=[_admin])
async def register_device(request: Request) -> JSONResponse:
    body = await request.json()
    return _passthrough(await relay_request(request, "POST", "/devices", json=body))


@router.put("/devices/{hostname}", dependencies=[_admin])
async def update_device(hostname: str, request: Request) -> JSONResponse:
    # PUT replaces a device's config; the gateway preserves any field the body omits
    # (including stored credentials when `auth` is omitted).
    body = await request.json()
    return _passthrough(await relay_request(request, "PUT", f"/devices/{hostname}", json=body))


@router.delete("/devices/{hostname}", dependencies=[_admin])
async def delete_device(hostname: str, request: Request) -> JSONResponse:
    return _passthrough(await relay_request(request, "DELETE", f"/devices/{hostname}"))


# --- Dead-letter queue (gateway F-10; distributed mode only) ------------------
#
# Inspect is a read; replay/drain mutate, so they require an admin session. The
# gateway returns 400 in embedded mode (no in-process DLQ), passed through here.


async def _optional_body(request: Request) -> Any:
    """The optional ``{"ids": [...]}`` selector body, or None when absent."""
    try:
        return await request.json()
    except Exception:
        return None


@router.get("/devices/{hostname}/deadletter", dependencies=[_any])
async def deadletter_list(hostname: str, request: Request) -> JSONResponse:
    return _passthrough(await relay_get(request, f"/devices/{hostname}/deadletter"))


@router.post("/devices/{hostname}/deadletter/replay", dependencies=[_admin])
async def deadletter_replay(hostname: str, request: Request) -> JSONResponse:
    # Optional {"ids": [...]} replays specific entries; no body replays the oldest batch.
    body = await _optional_body(request)
    return _passthrough(await relay_request(request, "POST", f"/devices/{hostname}/deadletter/replay", json=body))


@router.delete("/devices/{hostname}/deadletter", dependencies=[_admin])
async def deadletter_drain(hostname: str, request: Request) -> JSONResponse:
    # Optional {"ids": [...]} drains specific entries; no body drains the whole queue.
    body = await _optional_body(request)
    return _passthrough(await relay_request(request, "DELETE", f"/devices/{hostname}/deadletter", json=body))


# --- Monitoring (Prometheus / Loki) -----------------------------------------
#
# The UI shows only a few critical at-a-glance metrics and recent logs; full
# dashboards belong in central monitoring (most customers already run one). The
# BFF proxies a configured Prometheus / Loki so the browser never talks to them
# directly, and `monitoring/meta` tells the UI what is wired up + the central
# Grafana link.


@router.get("/monitoring/meta", dependencies=[_any])
async def monitoring_meta(request: Request) -> JSONResponse:
    s = request.app.state.settings
    return JSONResponse(
        {
            "prometheus_enabled": bool(s.prometheus_url),
            "loki_enabled": bool(s.loki_url),
            "grafana_url": s.grafana_url or None,
        }
    )


@router.get("/metrics/summary", dependencies=[_any])
async def metrics_summary(request: Request) -> JSONResponse:
    return _passthrough(await relay_get(request, "/metrics/summary"))


@router.get("/prometheus/query", dependencies=[_any])
async def prometheus_query(query: str, request: Request) -> JSONResponse:
    # Proxy a Prometheus instant query for the critical-metric tiles. 501 until
    # PROMETHEUS_URL is configured (the UI then points operators at central monitoring).
    settings = request.app.state.settings
    if not settings.prometheus_url:
        return JSONResponse(status_code=501, content={"detail": "PROMETHEUS_URL not configured"})
    async with httpx.AsyncClient(base_url=settings.prometheus_url, timeout=10.0) as client:
        return _passthrough(await client.get("/api/v1/query", params={"query": query}))


@router.get("/logs", dependencies=[_any])
async def logs(
    request: Request, query: str = '{job="mcp-gateway"}', limit: int = 100, minutes: int = 60
) -> JSONResponse:
    # Proxy a LogQL range query to LOKI_URL for the recent-logs panel. The gateway
    # is never in the log path — the UI reads logs from the store via the BFF.
    settings = request.app.state.settings
    if not settings.loki_url:
        return JSONResponse(status_code=501, content={"detail": "LOKI_URL not configured — use your central logging"})
    end_ns = int(time.time() * 1_000_000_000)
    start_ns = end_ns - int(minutes) * 60 * 1_000_000_000
    capped = max(1, min(int(limit), _MAX_LOG_LIMIT))
    params = {"query": query, "limit": capped, "start": start_ns, "end": end_ns, "direction": "backward"}
    async with httpx.AsyncClient(base_url=settings.loki_url, timeout=10.0) as client:
        return _passthrough(await client.get("/loki/api/v1/query_range", params=params))
