# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Browser-facing API: proxies to the gateway (and, later, Prometheus/Loki).

Every route is session-gated. Reads need any authenticated session; mutations need
an admin session. The browser never sees the gateway token — the GatewayClient
attaches it server-side.
"""

from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import urljoin

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from ..audit import OUTCOME_DENIED, OUTCOME_ERROR, OUTCOME_SUCCESS, outcome_for, record_request
from ..catalog_client import CatalogUnavailable
from ..relay import relay_get, relay_request
from ..security import (
    _persist_session,
    current_session,
    deny_password_session,
    require_role,
)

router = APIRouter(prefix="/api", tags=["api"])

_any = Depends(require_role())  # any authenticated session
_admin = Depends(require_role("admin"))
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


# --- Catalog claim (tenant plane, ADR-0020 §4) --------------------------------
#
# The claim itself is not a new gateway capability: it merges a device type's curated
# template with the tenant-supplied host/credential and calls the gateway's ordinary
# `POST /devices` (register_device above), unmodified. This does not touch or gate that
# route — the free-type DeviceForm keeps working exactly as it does today (ADR-0020 §3's
# "claiming is the only path" is a separate, not-yet-made decision, deliberately deferred).


def _tenant_id(request: Request) -> str:
    tenant_id = getattr(request.app.state.settings, "tenant_id", "") or ""
    if not tenant_id:
        # Fails closed like every other TENANT_ID-gated capability in this BFF (see
        # security.py's act-on-tenant check) rather than guessing which tenant a
        # catalog lookup is "for".
        raise HTTPException(status_code=503, detail="TENANT_ID not configured on this BFF")
    return tenant_id


async def _assigned_types(request: Request, tenant_id: str) -> list[dict]:
    catalog = request.app.state.catalog
    try:
        resp = await catalog.request("GET", f"/tenants/{tenant_id}/assignments")
    except CatalogUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        raise HTTPException(status_code=resp.status_code, detail=detail)
    return resp.json()["device_types"]


@router.get("/catalog/device-types", dependencies=[_any])
async def tenant_catalog(request: Request) -> JSONResponse:
    """This tenant's currently assigned device types (ADR-0020 §2) — what the "claim from
    catalog" view lists. Not assigned reads as an empty list here deliberately: unlike the
    catalog service itself, THIS route's own unavailability is what must read as a named
    condition (the 503 above), not the ordinary "nothing assigned" case."""
    tenant_id = _tenant_id(request)
    return JSONResponse(content={"device_types": await _assigned_types(request, tenant_id)})


@router.get("/catalog/device-types/{type_id}", dependencies=[_any])
async def tenant_catalog_detail(type_id: str, request: Request) -> JSONResponse:
    """One assigned type's version detail — what the claim form reads to know which
    credential fields to ask for (`auth_kind`). Scoped to types actually assigned to this
    tenant: unlike the provider console, a tenant has no legitimate reason to browse the
    wider catalog, only what has been offered to them."""
    tenant_id = _tenant_id(request)
    assigned = {t["id"] for t in await _assigned_types(request, tenant_id)}
    if type_id not in assigned:
        raise HTTPException(status_code=404, detail="not assigned to this tenant")
    catalog = request.app.state.catalog
    try:
        resp = await catalog.request("GET", f"/device-types/{type_id}")
    except CatalogUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return _passthrough(resp)


@router.post("/catalog/{type_id}/claim", dependencies=[_admin])
async def claim_device_type(type_id: str, request: Request) -> JSONResponse:
    """Merge the device type's current curated version with the tenant-supplied host/
    credential and register it via the gateway's existing `POST /devices` (ADR-0020 §4).

    Two calls, two audit records, matching this BFF's existing two-call pattern (e.g.
    restore's prepare+download): the device registration itself, and a best-effort
    follow-up to the catalog service pinning which version was claimed. The second call's
    failure does NOT undo the first's success — the device is already real by then — it is
    instead surfaced as its own named audit outcome (`device.claim.pin_unrecorded`) so an
    operator can find and backfill it once the catalog recovers, rather than being silently
    lost, which would just leave slice 5's upgrade-offer diff with no baseline and no trace
    of why.
    """
    tenant_id = _tenant_id(request)
    assigned = {t["id"] for t in await _assigned_types(request, tenant_id)}
    if type_id not in assigned:
        raise HTTPException(status_code=403, detail="this device type is not assigned to your tenant")

    catalog = request.app.state.catalog
    try:
        detail_resp = await catalog.request("GET", f"/device-types/{type_id}")
    except CatalogUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if detail_resp.status_code != 200:
        return _passthrough(detail_resp)
    versions = detail_resp.json()["versions"]
    current = max(versions, key=lambda v: v["version"])

    body = await request.json()
    hostname = body.get("hostname")
    base_url = body.get("base_url")

    # ADR-0020 §4c: who supplies the address is a property of the TYPE, declared by the
    # curator, and independent of who supplies the credential — a host-fixed type is not a §6
    # provider-operated service, so the tenant still brings their own key below.
    #
    # A tenant-supplied address is REFUSED here rather than overridden, which is the opposite
    # of what happens to `api_key_location` a few lines down, and the difference is the point.
    # A guessed key position is noise the curator can correct; a different address is a
    # disagreement about where the device *is*. Overriding it silently would leave a tenant
    # believing they had pointed the device somewhere they had not — the same condition
    # `_check_host_source` refuses on the curation side, where a `fixed_base_url` under
    # tenant sourcing is rejected precisely because nothing would read it.
    if current.get("host_source") == "provider_fixed":
        if base_url:
            raise HTTPException(
                status_code=400,
                detail=(
                    "this device type supplies its own address (ADR-0020 §4c) — remove base_url "
                    "rather than have it silently ignored"
                ),
            )
        base_url = current.get("fixed_base_url")
        if not base_url:
            # Unreachable through curation, which refuses the pair at write time and has a
            # CHECK constraint behind it. Reachable through a row that predates either, so it
            # fails here loudly instead of registering a device with base_url=None.
            raise HTTPException(
                status_code=502,
                detail="the catalog declares this type host-fixed but curated no address",
            )

    merged: dict[str, Any] = {
        "hostname": hostname,
        "base_url": base_url,
        "transport": current["transport"],
        "upstream_kind": current["upstream_kind"],
        "upstream_transport": current["upstream_transport"],
        "auth_type": current["auth_kind"],
    }
    if base_url and current.get("spec_path"):
        # Relative to the tenant's OWN base_url, never the curator's (schemas.py's
        # VersionFields.spec_path docstring, ADR-0020 §1) — joined here, at claim time,
        # which is the only point either half of this path is known together.
        root = base_url if base_url.endswith("/") else base_url + "/"
        merged["spec_url"] = urljoin(root, current["spec_path"].lstrip("/"))
    if current["auth_kind"] != "none":
        auth = dict(body.get("auth") or {})
        # WHERE the key goes is the provider's fact; the key itself is the tenant's. So the
        # curated position overrides whatever the browser sent, exactly as `transport` and
        # `spec_path` already do — a tenant who guesses `Authorization` instead of `X-API-Key`
        # gets a 401 at first contact that reads like a bad credential, not a misplaced one.
        #
        # Only when the curator actually said. `None` means a version predating these fields,
        # and falling back to the tenant's answer is right there: the alternative is
        # overwriting a working claim with a null.
        if current["auth_kind"] == "api_key":
            if current.get("api_key_location"):
                auth["location"] = current["api_key_location"]
            if current.get("api_key_name"):
                auth["name"] = current["api_key_name"]
        merged["auth"] = auth
    if current.get("fingerprint_policy"):
        merged["fingerprint_policy"] = current["fingerprint_policy"]
    # The tenant's answer wins — the curated figure is a RECOMMENDATION and pre-fills the
    # form, so what arrives here is already the tenant's decision, whether they kept it or
    # lowered it. Falling back to the recommendation only when nothing was sent covers the
    # API caller that never saw a form.
    if body.get("rate_limit_rps") is not None:
        merged["rate_limit_rps"] = body["rate_limit_rps"]
    elif current.get("recommended_rate_limit_rps") is not None:
        merged["rate_limit_rps"] = current["recommended_rate_limit_rps"]
    if body.get("expected_tls_spki_sha256"):
        merged["expected_tls_spki_sha256"] = body["expected_tls_spki_sha256"]

    resp = await relay_request(request, "POST", "/devices", json=merged)
    audited = await _audited(request, resp, "device.claim", target=str(hostname or "-"))
    if 200 <= resp.status_code < 300:
        try:
            await catalog.request(
                "POST",
                f"/device-types/{type_id}/claims",
                json={"tenant_id": tenant_id, "hostname": hostname, "version": current["version"]},
            )
        except CatalogUnavailable as exc:
            await record_request(
                request,
                "device.claim.pin_unrecorded",
                outcome=OUTCOME_ERROR,
                target=str(hostname or "-"),
                reason=str(exc),
            )
    return audited


@router.get("/catalog/upgrades", dependencies=[_any])
async def upgrade_offers(request: Request) -> JSONResponse:
    """Non-blocking, never scheduled, never forced (§4): a claimed device whose pinned
    version differs from what's currently curated, with a diff between the two versions'
    DECLARED tool sets when both have one. A read, so unaudited like the other catalog
    listings above — accepting an offer is the mutation below, audited there."""
    tenant_id = _tenant_id(request)
    catalog = request.app.state.catalog
    try:
        resp = await catalog.request("GET", f"/tenants/{tenant_id}/upgrades")
    except CatalogUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return _passthrough(resp)


@router.post("/catalog/upgrades/{hostname}/accept", dependencies=[_admin])
async def accept_upgrade(hostname: str, request: Request) -> JSONResponse:
    """Accepting an offer re-pins THIS device to the new curated version — it does not
    touch the gateway or the live device at all, unlike `claim_device_type` above (which
    registers a brand-new one). The catalog's own claims-recording route is idempotent on
    `(tenant_id, hostname)` (an UPSERT, see repo.py), so calling it again here with the
    new version is exactly re-pinning, nothing more."""
    tenant_id = _tenant_id(request)
    body = await request.json()
    device_type_id = body.get("device_type_id")
    version = body.get("version")
    if not device_type_id or not version:
        raise HTTPException(status_code=400, detail="'device_type_id' and 'version' are required")
    catalog = request.app.state.catalog
    try:
        resp = await catalog.request(
            "POST",
            f"/device-types/{device_type_id}/claims",
            json={"tenant_id": tenant_id, "hostname": hostname, "version": version},
        )
    except CatalogUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return await _audited(request, resp, "device.claim.upgrade_accepted", target=hostname)


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


@router.post("/devices/{hostname}/tools/{tool}/invoke", dependencies=[_admin])
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
        # unapproved fingerprint, an inactive pod, a scope the caller's credential lacks —
        # and rewriting it into "could not invoke" would cost the operator the one useful
        # sentence.
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


# --- Backup and restore --------------------------------------------------------
#
# No elevation here: ADR-0018 §6 (gateway repo) removed the credential dump these routes
# used to gate behind `provider:credentials` — an archive is configuration now, not a
# credential dump, so an ordinary admin session is the whole requirement.
#
# `_no_break_glass` stays on all three regardless: a password session proxies with the
# stack's admin token, which holds every `backup:*` scope, so admitting one here would
# still be a complete credential dump, just no longer one an elevation was ever gating.


@router.get("/admin/backup", dependencies=[_any, _no_break_glass, _admin])
async def export_backup(request: Request, include_deadletters: bool = False) -> JSONResponse:
    """The ciphertext archive. No secret in the request, so a GET is safe here."""
    resp = await relay_get(request, f"/admin/backup?include_deadletters={str(include_deadletters).lower()}")
    return await _audited(request, resp, "backup.export", target="registry")


@router.post("/admin/backup", dependencies=[_any, _no_break_glass, _admin])
async def export_backup_with_body(request: Request) -> JSONResponse:
    """Prepare an export: mint the archive, reveal the passphrase, hand back a download token.

    The first leg of the two-step. It returns **no archive** — only the passphrase (once) and
    a token — because the file has to arrive as a native browser download and a download
    cannot read the header the gateway delivers the passphrase in.

    What the BFF holds between the legs is worth being precise about: the archive body is
    **ciphertext in both kinds**. A ciphertext archive is sealed under `MCP_SECRET_KEY`, which
    only the gateway has; a portable one is sealed under the minted passphrase, which is
    handed to the browser and stored nowhere here. So the pending record is a blob this
    process cannot open — which is what makes parking it in the session for two minutes an
    acceptable trade rather than a credential cache.
    """
    body = await _optional_body(request)
    resp = await relay_request(request, "POST", "/admin/backup", json=body if isinstance(body, dict) else {})
    kind = (body or {}).get("kind") if isinstance(body, dict) else None
    action = "backup.export_portable" if kind == "portable" else "backup.export"

    if resp.status_code != 200:
        # Nothing was produced, so there is nothing to stage — pass the refusal straight back.
        return await _audited(request, resp, action, target="registry")

    sess = await current_session(request)
    token = secrets.token_urlsafe(32)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    pending = {
        "token": token,
        "kind": kind or "ciphertext",
        "filename": f"syncgate-backup-{kind or 'ciphertext'}-{stamp}.json",
        "body": resp.content.decode("utf-8", "replace"),
        "expires_at": time.time() + PENDING_BACKUP_TTL,
    }
    sess[PENDING_BACKUP] = pending
    await _persist_session(request, sess)

    # The archive and the passphrase are both absent from the audit detail: this chain records
    # that an export happened and by whom, never what it contained or what opens it.
    await record_request(request, action, outcome=outcome_for(resp.status_code), target="registry", staged=True)

    # The passphrase reaches the browser exactly here. The gateway mints it per export and
    # keeps no copy, and neither does this — so an operator who does not capture it now has
    # an archive nobody can open (ADR-0011, accepted).
    return JSONResponse(
        {
            "download_token": token,
            "filename": pending["filename"],
            "expires_at": pending["expires_at"],
            "passphrase": resp.headers.get("X-Backup-Passphrase"),
        }
    )


#: Where a prepared archive waits between the two legs of a download, and how long for.
#: Short because it is the whole window in which a token is worth stealing.
PENDING_BACKUP = "pending_backup"
PENDING_BACKUP_TTL = 120.0


@router.get("/admin/backup/download", dependencies=[_any, _no_break_glass])
async def download_backup(request: Request, token: str = ""):
    """Hand over the prepared archive as a file, once.

    The second leg of the two-step export. It exists because a native browser download cannot
    read a response header, and the passphrase is delivered in one — so a single request
    cannot give the operator both the file and the secret that opens it.

    Its authorization is carried by the pending record, which lives **in the session** — so
    the token is worthless to anyone else's browser, and the archive cannot be fetched by a
    leaked URL alone. What it still requires is the same gate as the export itself: never a
    break-glass session (`_no_break_glass`), because handing over this file is handing over
    the fleet.
    """
    sess = await current_session(request)
    pending = (sess or {}).get(PENDING_BACKUP)
    now = time.time()

    if not isinstance(pending, dict) or not token or not secrets.compare_digest(token, pending.get("token", "")):
        await record_request(request, "backup.download", outcome=OUTCOME_DENIED, reason="no_such_download")
        raise HTTPException(status_code=404, detail="No prepared archive for this session, or it has been claimed")
    if float(pending.get("expires_at", 0)) <= now:
        sess.pop(PENDING_BACKUP, None)
        await _persist_session(request, sess)
        await record_request(request, "backup.download", outcome=OUTCOME_DENIED, reason="expired")
        raise HTTPException(status_code=410, detail="The prepared archive expired; export again")

    # Single use: claimed before it is served, so a retried or replayed request finds nothing
    # even if the response never reaches the browser. Losing a download to a flaky network is
    # recoverable by exporting again; serving a credential dump twice is not.
    sess.pop(PENDING_BACKUP, None)
    await _persist_session(request, sess)
    await record_request(
        request, "backup.download", outcome=OUTCOME_SUCCESS, target="registry", kind=pending.get("kind")
    )
    return Response(
        content=pending["body"],
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{pending["filename"]}"'},
    )


@router.post("/admin/restore", dependencies=[_any, _no_break_glass, _admin])
async def restore_backup(request: Request) -> JSONResponse:
    """Preview or apply a restore. **A request that does not say otherwise is a dry run.**

    The gateway split this into two routes by scope (ADR-0018 §6): a dry run goes to
    `/admin/restore/preview`, a write to `/admin/restore/apply`, and only the second is
    destructive. `dry_run` no longer means anything to the gateway itself, but it stays
    the client-facing switch here and defaults to true anyway rather than relying on the
    upstream default — the destructive direction must not become reachable by omission
    through two layers, and a thin proxy quietly behaving differently from the system it
    wraps is a gap this project has shipped twice before. Divergence here can only fail
    safe: an unset or unparseable body always resolves to preview.

    An apply must carry `plan_token`, from a preceding preview of this exact request; the
    gateway refuses a missing, forged, or stale one with `ERR_PLAN_STALE` before writing
    anything, and that structured response is passed straight through.
    """
    body = await _optional_body(request)
    payload = dict(body) if isinstance(body, dict) else {}
    dry_run = bool(payload.pop("dry_run", True))
    path = "/admin/restore/preview" if dry_run else "/admin/restore/apply"
    resp = await relay_request(request, "POST", path, json=payload)
    action = "backup.restore" if not dry_run else "backup.restore_preview"
    return await _audited(request, resp, action, target="registry")
