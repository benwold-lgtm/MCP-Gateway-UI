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

from .config import load_settings
from .gateway_client import GatewayClient
from .routers import api, auth


def create_app() -> FastAPI:
    settings = load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            await app.state.gateway.aclose()

    app = FastAPI(title="Device MCP Gateway UI — BFF", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.gateway = GatewayClient(settings)

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
