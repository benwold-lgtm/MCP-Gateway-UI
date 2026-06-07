# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Login / logout / whoami — establishes a signed-cookie session with a role."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..security import current_role, resolve_role

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    password: str


@router.post("/login")
async def login(request: Request, body: LoginBody) -> dict:
    role = resolve_role(request.app.state.settings, body.password)
    if role is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session["role"] = role
    return {"role": role}


@router.post("/logout")
async def logout(request: Request) -> dict:
    request.session.clear()
    return {"status": "logged out"}


@router.get("/me")
async def me(request: Request) -> dict:
    role = current_role(request)
    if not role:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"role": role}
