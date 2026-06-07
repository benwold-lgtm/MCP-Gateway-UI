# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""BFF settings, loaded from the environment.

The gateway admin token lives here on the server only — it is NEVER sent to the
browser. The browser holds an opaque signed session cookie; the BFF translates a
session into upstream calls authenticated with the gateway token.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    gateway_url: str
    gateway_token: str
    ui_admin_password: str
    ui_viewer_password: str
    session_secret: str
    prometheus_url: str
    loki_url: str
    cors_origins: list[str] = field(default_factory=list)
    cookie_secure: bool = False


def _split(csv: str) -> list[str]:
    return [item.strip() for item in csv.split(",") if item.strip()]


def load_settings() -> Settings:
    return Settings(
        gateway_url=os.getenv("GATEWAY_URL", "http://localhost:8000"),
        # Admin bearer token for the gateway API (server-side only).
        gateway_token=os.getenv("GATEWAY_API_TOKEN", ""),
        # UI login passwords → role. Leave a role's password empty to disable it.
        ui_admin_password=os.getenv("UI_ADMIN_PASSWORD", ""),
        ui_viewer_password=os.getenv("UI_VIEWER_PASSWORD", ""),
        # MUST be overridden in production; signs the session cookie.
        session_secret=os.getenv("SESSION_SECRET", "dev-insecure-change-me"),
        prometheus_url=os.getenv("PROMETHEUS_URL", ""),
        loki_url=os.getenv("LOKI_URL", ""),
        cors_origins=_split(os.getenv("CORS_ORIGINS", "")),
        cookie_secure=os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
    )
