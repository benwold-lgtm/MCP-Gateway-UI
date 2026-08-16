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

from ..audit import outcome_for, record_request
from ..relay import relay_get, relay_request
from ..security import (
    SCOPE_PROVIDER_CREDENTIALS,
    SCOPE_PROVIDER_INVOKE,
    deny_password_session,
    require_elevated,
    require_role,
)

router = APIRouter(prefix="/api", tags=["api"])

_any = Depends(require_role())  # any authenticated session
_admin = Depends(require_role("admin"))
# Routes whose whole purpose is an elevated capability (ADR-0013 §5a/§8). The dependency
# marks the request so the elevated credential is relayed *only* here — see
# `security.require_elevated`. The closed list of routes carrying these is asserted in
# `tests/test_elevated_routes.py`; adding one to a route that does not need it silently
# spends single-use grants on routine traffic.
_needs_invoke = Depends(require_elevated(SCOPE_PROVIDER_INVOKE))
_needs_credentials = Depends(require_elevated(SCOPE_PROVIDER_CREDENTIALS))
_no_break_glass = Depends(deny_password_session)

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


async def _audited(request: Request, resp: httpx.Response, action: str, target: str | None = None) -> JSONResponse:
    """Pass an upstream response through, recording it in the BFF's audit chain first.

    Only *mutations* are audited here. Reads are deliberately not — with per-user OIDC
    relay the gateway's own chain already records the real human behind every proxied
    read, so auditing them again would duplicate rather than add. That changes when
    provider federation lands (ADR-0012): the gateway stops seeing the person, and reads
    by a human provider principal become exactly what ADR-0013 §9 says a tenant must see.
    """
    await record_request(request, action, outcome=outcome_for(resp.status_code), target=target, status=resp.status_code)
    return _passthrough(resp)


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
    resp = await relay_request(request, "POST", "/devices", json=body)
    return await _audited(request, resp, "device.register", target=str(body.get("hostname") or "-"))


@router.put("/devices/{hostname}", dependencies=[_admin])
async def update_device(hostname: str, request: Request) -> JSONResponse:
    # PUT replaces a device's config; the gateway preserves any field the body omits
    # (including stored credentials when `auth` is omitted).
    body = await request.json()
    resp = await relay_request(request, "PUT", f"/devices/{hostname}", json=body)
    return await _audited(request, resp, "device.update", target=hostname)


@router.delete("/devices/{hostname}", dependencies=[_admin])
async def delete_device(hostname: str, request: Request) -> JSONResponse:
    resp = await relay_request(request, "DELETE", f"/devices/{hostname}")
    return await _audited(request, resp, "device.delete", target=hostname)


@router.post("/devices/{hostname}/fingerprint/approve", dependencies=[_admin])
async def approve_fingerprint(hostname: str, request: Request) -> JSONResponse:
    """Re-pin a device to the key it is now presenting (gateway ADR-0015 §6).

    Admin-gated because the gateway requires `devices:write`, and audited under the
    *same* action name the gateway uses — the two chains then line up on one event
    instead of describing it twice in different words.

    The gateway answers 409 when the device is not actually pending (or is pending with
    no recorded key), and that passes straight through: approving from a stale screen
    should fail visibly rather than look like it worked.
    """
    resp = await relay_request(request, "POST", f"/devices/{hostname}/fingerprint/approve")
    return await _audited(request, resp, "device.fingerprint.approve", target=hostname)


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
    resp = await relay_request(request, "POST", f"/devices/{hostname}/deadletter/replay", json=body)
    return await _audited(request, resp, "deadletter.replay", target=hostname)


@router.delete("/devices/{hostname}/deadletter", dependencies=[_admin])
async def deadletter_drain(hostname: str, request: Request) -> JSONResponse:
    # Optional {"ids": [...]} drains specific entries; no body drains the whole queue.
    body = await _optional_body(request)
    resp = await relay_request(request, "DELETE", f"/devices/{hostname}/deadletter", json=body)
    return await _audited(request, resp, "deadletter.drain", target=hostname)


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


# --- Tool invocation (ADR-0013 §8 provider:invoke) ----------------------------
#
# Not a proxy of `/v1/devices/{h}/mcp`. That path is the full MCP streamable transport:
# `initialize` mints the session id server-side, and a sessionless call carrying an `id` is
# refused with 400. A bare `tools/call` cannot be forwarded, so the BFF runs the handshake
# and hands back the result on its own.
#
# **What this shape gives up, deliberately:** collapsing the exchange into one blocking
# response means no incremental progress for a long-running call. Measured before choosing
# it — the gateway's dispatch contract is `exchange() -> dict | None`, one request and one
# response, and inbound `notifications/*` return None. No transport can surface progress
# today, so the console loses nothing a transparent proxy would have given it. Revisit if
# the gateway grows a streaming result channel; this route then gains a streaming sibling
# rather than being replaced.

_MCP_ACCEPT = "application/json, text/event-stream"
_MCP_SESSION_HEADER = "Mcp-Session-Id"
_MCP_PROTOCOL_VERSION = "2025-06-18"


async def _mcp(request: Request, hostname: str, payload: dict, session_id: str | None = None) -> httpx.Response:
    headers = {"Accept": _MCP_ACCEPT}
    if session_id:
        headers[_MCP_SESSION_HEADER] = session_id
        headers["MCP-Protocol-Version"] = _MCP_PROTOCOL_VERSION
    return await relay_request(request, "POST", f"/devices/{hostname}/mcp", json=payload, headers=headers)


@router.post("/devices/{hostname}/tools/{tool}/invoke", dependencies=[_admin, _needs_invoke])
async def invoke_tool(hostname: str, tool: str, request: Request) -> JSONResponse:
    """Call one tool on one device and return its result.

    Three upstream calls — initialize, tools/call, delete — presented as one. The teardown
    is best effort *and does not need to succeed*: gateway MCP sessions carry their own
    24-hour expiry in distributed mode, so a BFF that dies mid-sequence leaks one Redis hash
    for at most a day rather than a session forever.
    """
    body = await _optional_body(request)
    arguments = (body or {}).get("arguments") if isinstance(body, dict) else None
    if arguments is not None and not isinstance(arguments, dict):
        return JSONResponse(status_code=400, content={"detail": "'arguments' must be an object"})

    opened = await _mcp(
        request,
        hostname,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-gateway-console", "version": "1"},
            },
        },
    )
    if opened.status_code >= 400:
        # Pass the handshake's own refusal through unchanged. It carries the reason — an
        # unapproved fingerprint, an inactive pod, a refused elevation — and rewriting it
        # into "could not invoke" would cost the operator the one useful sentence.
        return await _audited(request, opened, "tool.invoke", target=f"{hostname}/{tool}")

    session_id = opened.headers.get(_MCP_SESSION_HEADER)
    if not session_id:
        return JSONResponse(
            status_code=502,
            content={"detail": "the gateway accepted the MCP handshake without returning a session id"},
        )

    try:
        called = await _mcp(
            request,
            hostname,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": arguments or {}}},
            session_id=session_id,
        )
    finally:
        try:
            await relay_request(
                request,
                "DELETE",
                f"/devices/{hostname}/mcp",
                headers={"Accept": _MCP_ACCEPT, _MCP_SESSION_HEADER: session_id},
            )
        except Exception:  # noqa: BLE001 - teardown must never mask the call's own outcome
            pass

    return await _audited(request, called, "tool.invoke", target=f"{hostname}/{tool}")


# --- Backup and restore (ADR-0013 §5b/§8 provider:credentials) ----------------
#
# `_no_break_glass` on all three: a password session proxies with the stack's admin token,
# which holds every `backup:*` scope, so admitting one here is a complete credential dump
# with no step-up behind it and nothing in either audit chain naming a grant.


@router.get("/admin/backup", dependencies=[_any, _no_break_glass, _needs_credentials])
async def export_backup(request: Request, include_deadletters: bool = False) -> JSONResponse:
    """The ciphertext archive. No secret in the request, so a GET is safe here."""
    resp = await relay_get(request, f"/admin/backup?include_deadletters={str(include_deadletters).lower()}")
    return await _audited(request, resp, "backup.export", target="registry")


@router.post("/admin/backup", dependencies=[_any, _no_break_glass, _needs_credentials])
async def export_backup_with_body(request: Request) -> JSONResponse:
    """Either archive kind. The passphrase for a portable export travels in the body — never
    a query string, which would be written to every access log between here and the gateway."""
    body = await _optional_body(request)
    resp = await relay_request(request, "POST", "/admin/backup", json=body if isinstance(body, dict) else {})
    kind = (body or {}).get("kind") if isinstance(body, dict) else None
    action = "backup.export_portable" if kind == "portable" else "backup.export"
    # The archive and any passphrase are deliberately absent from the audit detail: this
    # chain records that an export happened and by whom, never what it contained.
    return await _audited(request, resp, action, target="registry")


@router.post("/admin/restore", dependencies=[_any, _no_break_glass, _needs_credentials])
async def restore_backup(request: Request) -> JSONResponse:
    """Replay an archive. **A request that does not say otherwise is a dry run.**

    The gateway defaults `dry_run` to true itself, and this sets it anyway rather than
    relying on that. The destructive direction must not be reachable by omission through two
    layers, and a thin proxy quietly behaving differently from the system it wraps is a gap
    this project has shipped twice before. Divergence here can only fail safe.
    """
    body = await _optional_body(request)
    payload = dict(body) if isinstance(body, dict) else {}
    payload["dry_run"] = bool(payload.get("dry_run", True))
    resp = await relay_request(request, "POST", "/admin/restore", json=payload)
    action = "backup.restore" if not payload["dry_run"] else "backup.restore_preview"
    return await _audited(request, resp, action, target="registry")
