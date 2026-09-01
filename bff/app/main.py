# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""BFF application factory.

  Browser ──(signed cookie: session id)──> BFF ──(gateway bearer token)──> Gateway API
                                              └──> Prometheus / Loki (monitoring, phase 2)

The gateway token is held only here. The browser's cookie carries just an opaque
session id; session content (role, OIDC tokens) lives in the server-side store
(app/sessions.py — in-memory by default, Redis via SESSION_REDIS_URL).
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .audit import AuditLog, Pseudonymizer, TenantKeyring
from .bootstrap import apply_first_run_bootstrap
from .catalog_client import CatalogClient
from .catalog_enrolment import gateway_resolver
from .config import DEFAULT_SESSION_SECRET, load_settings
from .correlation import CORRELATION_HEADER, use_request_id
from .gateway_client import GatewayClient
from .gateway_pool import TenantGatewayPool
from .oidc import OIDCClient
from .routers import api, auth, catalog, enrolment, provider, support
from .sessions import MemorySessionStore, RedisSessionStore
from .tenant_directory import TenantDirectory
from .tenant_registry import TenantRegistryError, load_tenant_registry
from .throttle import LoginThrottle, parse_trusted_proxy_cidrs


def create_app() -> FastAPI:
    settings = load_settings()
    # LITE first-run bootstrap: when BFF_STATE_DIR is set, fill in any secret the operator
    # didn't provide (generating + persisting it) so a home box runs without hand-config.
    # No-op otherwise, so the fail-closed check below still guards enterprise deploys.
    settings = apply_first_run_bootstrap(settings)

    # Fail closed on an insecure session secret in production. COOKIE_SECURE=true is the
    # "behind TLS / production" signal. The cookie now carries only a session id, but the
    # secret still signs the OIDC login transaction (state/nonce/PKCE verifier) — a
    # publicly-known key would let an attacker tamper with it (login CSRF). In dev
    # (COOKIE_SECURE unset) the default is allowed for convenience.
    if settings.cookie_secure and settings.session_secret == DEFAULT_SESSION_SECRET:
        raise RuntimeError(
            "SESSION_SECRET is the insecure default while COOKIE_SECURE is enabled. "
            "Set SESSION_SECRET to a strong random value (e.g. `openssl rand -hex 32`) — "
            "it signs the session-id cookie and the OIDC login transaction."
        )

    # ADR-0013 §5, enforced rather than advised. A tenant's BFF lives inside the tenant's
    # stack, so carrying the provider IdP there puts cross-tenant machinery inside the
    # per-tenant isolation unit — the same mistake §5 refuses for the gateway, and the only
    # topology in which a cross-plane leak is possible at all. A README paragraph is not a
    # control; §11 rejected a whole design option on exactly that ground.
    if settings.oidc_enabled and settings.provider_oidc_enabled:
        raise RuntimeError(
            "Both OIDC_ENABLED (tenant plane) and PROVIDER_OIDC_ENABLED (provider plane) are set. "
            "A tenant-stack BFF must not carry the provider IdP (ADR-0013 §2/§5). Deploy the "
            "provider console separately: it sets PROVIDER_OIDC_* and leaves OIDC_* unset. "
            "Break-glass password login stays available in both."
        )

    # Per-tenant subdomains are only an isolation boundary while the session cookie is
    # scoped to the host that set it. A cookie on `.example.com` is sent to every tenant
    # portal under it, so one tenant's console can carry another's session — and nothing
    # breaks, which is what makes it worth a startup refusal rather than a warning.
    #
    # There is no supported value: the cookie is host-scoped by construction (no `domain` is
    # passed to SessionMiddleware below), and a value equal to the host is merely redundant.
    # The setting is read *only* so that the attempt is made here, where it can be refused,
    # rather than at a reverse proxy where nothing in this process can see it.
    if settings.cookie_domain:
        raise RuntimeError(
            f"COOKIE_DOMAIN is set ({settings.cookie_domain!r}). The BFF session cookie is "
            "deliberately host-scoped: under per-tenant subdomains a parent-domain cookie is "
            "sent to every tenant's console, so one tenant's browser session reaches another's "
            "portal while everything appears to work. Unset it. If you are trying to share a "
            "session across hostnames, that is the boundary this refuses to cross."
        )

    # ADR-0021 (scoped): fails at boot on a malformed PROVIDER_TENANT_REGISTRY rather than
    # on the first request that needed an entry (the same posture as the checks above).
    try:
        tenant_registry = load_tenant_registry(settings.provider_tenant_registry)
    except TenantRegistryError as exc:
        raise RuntimeError(str(exc)) from exc

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await app.state.gateway.aclose()
            await app.state.gateway_pool.aclose()
            await app.state.catalog.aclose()
            await app.state.sessions.aclose()

    app = FastAPI(title="Device MCP Gateway UI — BFF", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.gateway = GatewayClient(settings)
    # ADR-0020. Constructed unconditionally (like GatewayClient) — CatalogClient itself
    # reports "not configured" as CatalogUnavailable per-call, rather than this being a
    # None the routers below would each have to check for separately.
    # ADR-0024 §10: on a tenant console, when env named no catalog, learn it from this
    # tenant's own enrolment instead — enrolling becomes sufficient on its own, with no
    # credential to copy and no restart. Never on a provider console: it holds the privileged
    # credential from its own configuration and is the party others enrol *with*, so asking a
    # gateway for one would be the misdelivery ADR-0020 §7b exists to catch.
    resolver = None if settings.provider_oidc_enabled else gateway_resolver(app.state.gateway)
    app.state.catalog = CatalogClient(settings, resolver=resolver)
    app.state.tenant_registry = tenant_registry
    # ADR-0024 §11: config is the floor, the catalog's `tenants` table is the live source. The
    # directory starts holding only what config named and learns the enrolled estate on its
    # first refresh, so a console whose catalog is down at boot still knows its tenants.
    app.state.tenant_directory = TenantDirectory(tenant_registry)
    app.state.gateway_pool = TenantGatewayPool(
        app.state.tenant_directory,
        gateway_api_prefix=settings.gateway_api_prefix,
        catalog=app.state.catalog,
    )
    # Server-side session store: memory for a single replica (lite/dev); Redis when
    # SESSION_REDIS_URL is set, which multi-replica deploys need (no session affinity).
    # Namespaced per deployment. The startup refusal above is per-process and the store is
    # not: two BFFs sharing one SESSION_REDIS_URL would otherwise share `bff:sess:{sid}`
    # and resolve each other's session ids. The plane wall still holds if that happens,
    # which is why both controls exist rather than either alone.
    session_ns = "provider" if settings.provider_oidc_enabled else f"tenant:{settings.audit_tenant}"
    app.state.sessions = (
        RedisSessionStore(settings.session_redis_url, ttl=settings.session_ttl_seconds, namespace=session_ns)
        if settings.session_redis_url
        else MemorySessionStore(ttl=settings.session_ttl_seconds)
    )
    # OIDC Relying Party (ADR-0007). None unless OIDC_ENABLED and the issuer/client are
    # configured — a misconfiguration fails fast here rather than on the first login.
    app.state.oidc = OIDCClient(settings) if settings.oidc_enabled else None
    # The provider plane's own RP (ADR-0013 §2). None on a tenant-stack BFF, which is
    # what a tenant deployment should look like — see the README topology note.
    app.state.provider_oidc = OIDCClient.for_provider(settings) if settings.provider_oidc_enabled else None
    # Brute-force throttle for the break-glass password login (review #3).
    app.state.login_throttle = LoginThrottle(
        max_failures=settings.login_max_failures,
        window=settings.login_window_seconds,
    )
    # Parsed once here, not per request: an invalid CIDR must stop the deployment at
    # startup, where it is attributable, rather than raising on some later login attempt --
    # and re-parsing a trust set on every request to a login route is work with no purpose.
    app.state.trusted_proxy_cidrs = parse_trusted_proxy_cidrs(settings.trusted_proxy_cidrs)
    # Hash-chained audit (gateway F-57 model, ADR-0013 §9/§10). Built here rather than
    # lazily so the chain re-seeds from its own tail once, at startup, instead of racing
    # the first request.
    keyring = TenantKeyring()
    if settings.audit_content_key:
        keyring.add(settings.audit_tenant, settings.audit_content_key.encode("ascii"))
    else:
        print(
            "[audit] AUDIT_CONTENT_KEY is not set — audit content is written in the clear "
            "and this tenant cannot be crypto-shredded on offboarding (ADR-0013 §10).",
            flush=True,
        )
    app.state.audit = AuditLog(
        path=settings.audit_path or None,
        tenant=settings.audit_tenant,
        keyring=keyring,
        pseudonymizer=Pseudonymizer(
            settings.audit_pseudonym_key.encode("utf-8") if settings.audit_pseudonym_key else None
        ),
    )

    # ADR-0026: a human's action starts here, so the correlation id does too. Minted when
    # the browser supplies none, bound for the whole downstream call so every outbound hop
    # (the tenant gateway, another tenant's gateway through the relay pool, the catalog)
    # carries it, returned to the browser, and recorded on this request's audit row. The
    # gateway honours an inbound X-Request-Id, so one id spans console click → gateway →
    # device rather than only the gateway's half of the journey.
    @app.middleware("http")
    async def correlate(request, call_next):
        rid = request.headers.get(CORRELATION_HEADER) or str(uuid.uuid4())
        with use_request_id(rid):
            response = await call_next(request)
        response.headers[CORRELATION_HEADER] = rid
        return response

    # Signed-cookie session. same_site=lax + httponly; set COOKIE_SECURE=true behind TLS.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        same_site="lax",
        https_only=settings.cookie_secure,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # ADR-0021 (scoped): the tenant deployment (the default — what any enterprise runs) and
    # the provider deployment (the add-on) mount different route surfaces.
    #
    # `api.router` (the tenant data plane, `/api/*`) is common to both, unlike the other
    # three: a tenant session uses it directly, and a provider session relays through it too
    # once it holds a delegated support grant (`relay.py`'s per-tenant pool resolution,
    # ADR-0021 scoped slices 2/3) — mounting it only on a tenant deployment would break that
    # mechanism outright, not merely narrow it.
    #
    # `provider.router`/`catalog.router` require a provider-plane session
    # (`require_provider_scope`) that a tenant session can never hold, so they are
    # provider-only. `support.router` requires `require_role`, which only ever admits a
    # provider session while it holds *some* grant — the gateway is what enforces whether
    # that grant's approved scopes actually cover a tenant-governance action like approving
    # or revoking another request (see `require_role`'s own docstring) — so it is tenant-only
    # here for the same reason the other two are provider-only: no session on the other side
    # can ever pass its gate, gating this exists purely for a leaner API surface.
    #
    # `auth.router` carries login for both planes plus the shared break-glass path.
    app.include_router(auth.router)
    app.include_router(api.router)
    if settings.provider_oidc_enabled:
        app.include_router(provider.router)
        app.include_router(catalog.router)
        # ADR-0024 §10: redeeming a tenant's invitation. Provider-plane by construction, like
        # the two above — enrolling is the provider's act, and the tenant's half of the
        # handshake happens in the tenant's own console.
        app.include_router(enrolment.router)
    else:
        app.include_router(support.router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
