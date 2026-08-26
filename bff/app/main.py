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

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .audit import AuditLog, Pseudonymizer, TenantKeyring
from .bootstrap import apply_first_run_bootstrap
from .catalog_client import CatalogClient
from .config import DEFAULT_SESSION_SECRET, load_settings
from .gateway_client import GatewayClient
from .oidc import OIDCClient
from .routers import api, auth, catalog, provider, support
from .sessions import MemorySessionStore, RedisSessionStore
from .throttle import LoginThrottle


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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await app.state.gateway.aclose()
            await app.state.catalog.aclose()
            await app.state.sessions.aclose()

    app = FastAPI(title="Device MCP Gateway UI — BFF", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.gateway = GatewayClient(settings)
    # ADR-0020. Constructed unconditionally (like GatewayClient) — CatalogClient itself
    # reports "not configured" as CatalogUnavailable per-call, rather than this being a
    # None the routers below would each have to check for separately.
    app.state.catalog = CatalogClient(settings)
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

    app.include_router(auth.router)
    app.include_router(api.router)
    app.include_router(catalog.router)
    app.include_router(provider.router)
    app.include_router(support.router)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
