# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
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
    gateway_api_prefix: str
    gateway_token: str
    ui_admin_password: str
    ui_viewer_password: str
    session_secret: str
    prometheus_url: str
    loki_url: str
    grafana_url: str = ""
    cors_origins: list[str] = field(default_factory=list)
    cookie_secure: bool = False
    # Federated identity (OIDC, ADR-0007). When enabled, the BFF runs an Authorization
    # Code + PKCE login against the IdP and relays the user's access token upstream
    # (Mode A token passthrough), so the gateway authorizes the real user. Local
    # password login stays available as break-glass/bootstrap.
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_post_login_redirect: str = "/"


def _split(csv: str) -> list[str]:
    return [item.strip() for item in csv.split(",") if item.strip()]


def load_settings() -> Settings:
    return Settings(
        gateway_url=os.getenv("GATEWAY_URL", "http://localhost:8000"),
        # The gateway versions its management API under a prefix (e.g. /v1/devices).
        # Override only when the gateway introduces a new version (e.g. /v2). The
        # unversioned probes (/health, /readyz) are not proxied by the BFF.
        gateway_api_prefix=os.getenv("GATEWAY_API_PREFIX", "/v1"),
        # Admin bearer token for the gateway API (server-side only).
        gateway_token=os.getenv("GATEWAY_API_TOKEN", ""),
        # UI login passwords → role. Leave a role's password empty to disable it.
        ui_admin_password=os.getenv("UI_ADMIN_PASSWORD", ""),
        ui_viewer_password=os.getenv("UI_VIEWER_PASSWORD", ""),
        # MUST be overridden in production; signs the session cookie.
        session_secret=os.getenv("SESSION_SECRET", "dev-insecure-change-me"),
        prometheus_url=os.getenv("PROMETHEUS_URL", ""),
        loki_url=os.getenv("LOKI_URL", ""),
        # Optional link to central Grafana — surfaced in the UI's monitoring view so
        # operators jump to full dashboards rather than rebuilding them here.
        grafana_url=os.getenv("GRAFANA_URL", ""),
        cors_origins=_split(os.getenv("CORS_ORIGINS", "")),
        cookie_secure=os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
        # OIDC (federated identity). Disabled unless OIDC_ENABLED is truthy AND an
        # issuer + client id are configured (validated in OIDCClient).
        oidc_enabled=os.getenv("OIDC_ENABLED", "false").lower() in ("1", "true", "yes"),
        oidc_issuer=os.getenv("OIDC_ISSUER", ""),
        oidc_client_id=os.getenv("OIDC_CLIENT_ID", ""),
        oidc_client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
        # Must exactly match a redirect URI registered with the IdP, e.g.
        # https://ui.example.com/auth/oidc/callback
        oidc_redirect_url=os.getenv("OIDC_REDIRECT_URL", ""),
        oidc_scopes=os.getenv("OIDC_SCOPES", "openid profile email"),
        oidc_post_login_redirect=os.getenv("OIDC_POST_LOGIN_REDIRECT", "/"),
    )
