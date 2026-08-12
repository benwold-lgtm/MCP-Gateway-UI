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
from .config import DEFAULT_SESSION_SECRET, load_settings
from .gateway_client import GatewayClient
from .oidc import OIDCClient
from .routers import api, auth
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

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await app.state.gateway.aclose()
            await app.state.sessions.aclose()

    app = FastAPI(title="Device MCP Gateway UI — BFF", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.gateway = GatewayClient(settings)
    # Server-side session store: memory for a single replica (lite/dev); Redis when
    # SESSION_REDIS_URL is set, which multi-replica deploys need (no session affinity).
    app.state.sessions = (
        RedisSessionStore(settings.session_redis_url, ttl=settings.session_ttl_seconds)
        if settings.session_redis_url
        else MemorySessionStore(ttl=settings.session_ttl_seconds)
    )
    # OIDC Relying Party (ADR-0007). None unless OIDC_ENABLED and the issuer/client are
    # configured — a misconfiguration fails fast here rather than on the first login.
    app.state.oidc = OIDCClient(settings) if settings.oidc_enabled else None
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

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
