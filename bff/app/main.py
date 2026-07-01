# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""BFF application factory.

  Browser ──(signed session cookie)──> BFF ──(gateway bearer token)──> Gateway API
                                          └──> Prometheus / Loki (monitoring, phase 2)

The gateway token is held only here; the browser holds an opaque session cookie.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .config import DEFAULT_SESSION_SECRET, load_settings
from .gateway_client import GatewayClient
from .oidc import OIDCClient
from .routers import api, auth
from .throttle import LoginThrottle


def create_app() -> FastAPI:
    settings = load_settings()

    # Fail closed on an insecure session secret in production. COOKIE_SECURE=true is the
    # "behind TLS / production" signal; refusing to boot here prevents a deploy that signs
    # session cookies (role + relayed access token) with a publicly-known key. In dev
    # (COOKIE_SECURE unset) the default is allowed for convenience.
    if settings.cookie_secure and settings.session_secret == DEFAULT_SESSION_SECRET:
        raise RuntimeError(
            "SESSION_SECRET is the insecure default while COOKIE_SECURE is enabled. "
            "Set SESSION_SECRET to a strong random value (e.g. `openssl rand -hex 32`) — "
            "the session cookie carries the role and the relayed access token."
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await app.state.gateway.aclose()

    app = FastAPI(title="Device MCP Gateway UI — BFF", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.gateway = GatewayClient(settings)
    # OIDC Relying Party (ADR-0007). None unless OIDC_ENABLED and the issuer/client are
    # configured — a misconfiguration fails fast here rather than on the first login.
    app.state.oidc = OIDCClient(settings) if settings.oidc_enabled else None
    # Brute-force throttle for the break-glass password login (review #3).
    app.state.login_throttle = LoginThrottle(
        max_failures=settings.login_max_failures,
        window=settings.login_window_seconds,
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
