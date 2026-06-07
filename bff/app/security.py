# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Session roles and authorization for the BFF.

Mirrors the gateway's role model (admin / viewer) at the UI tier. The session holds
only an opaque role string in a signed cookie — never the gateway token. Mutations
require an admin session; reads allow any authenticated session.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

ROLES = ("admin", "viewer")


def resolve_role(settings, password: str) -> str | None:
    """Map a login password to a role using constant-time comparison."""
    if settings.ui_admin_password and hmac.compare_digest(password, settings.ui_admin_password):
        return "admin"
    if settings.ui_viewer_password and hmac.compare_digest(password, settings.ui_viewer_password):
        return "viewer"
    return None


def current_role(request: Request) -> str | None:
    return request.session.get("role")


def require_role(*allowed: str):
    """Dependency factory: 401 if no session, 403 if the role isn't permitted."""

    async def _dep(request: Request) -> str:
        role = current_role(request)
        if not role:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if allowed and role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return role

    return _dep
