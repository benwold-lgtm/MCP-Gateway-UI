# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Server-side session store.

The browser cookie no longer carries the role or any OIDC token — only a random
session id (``sid``), still signed and HttpOnly via the existing SessionMiddleware.
Session content lives server-side in one of two backends:

* :class:`MemorySessionStore` — the default. A TTL'd in-process dict; right for the
  lite/dev single-replica deployment. Sessions drop on restart (users log in again).
* :class:`RedisSessionStore` — enabled by ``SESSION_REDIS_URL``. Required when the
  BFF runs more than one replica (the K8s overlay runs 2) since there is no session
  affinity; also survives restarts.

Each backend provides a per-session async lock, used by
:func:`app.relay.refresh_oidc_access_token` to serialise OIDC token refresh — with
refresh-token rotation, two racing refreshes could otherwise invalidate one
another (the race the cookie-based design documented as out of scope).
"""

from __future__ import annotations

import asyncio
import copy
import json
import secrets
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import Request

#: Key inside the signed cookie session. The only other cookie tenant is the
#: short-lived ``oidc_tx`` login transaction (state/nonce/PKCE verifier).
COOKIE_SID_KEY = "sid"

_UNSET = object()  # request.state cache sentinel — None is a valid cached value


class SessionStore(ABC):
    """TTL'd mapping of session id → session dict, plus a per-session lock."""

    @abstractmethod
    async def get(self, sid: str) -> Optional[dict]: ...

    @abstractmethod
    async def set(self, sid: str, data: dict) -> None:
        """Store ``data`` under ``sid`` and (re)start its TTL."""

    @abstractmethod
    async def delete(self, sid: str) -> None: ...

    @abstractmethod
    def lock(self, sid: str) -> AsyncIterator[None]:
        """Async context manager serialising critical sections for one session."""

    async def aclose(self) -> None:  # pragma: no cover - trivial default
        return None


class MemorySessionStore(SessionStore):
    def __init__(self, ttl: int) -> None:
        self._ttl = ttl
        self._data: dict[str, tuple[float, dict]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        for sid in [s for s, (exp, _) in self._data.items() if exp <= now]:
            del self._data[sid]
            lock = self._locks.get(sid)
            if lock is not None and not lock.locked():
                del self._locks[sid]

    async def get(self, sid: str) -> Optional[dict]:
        entry = self._data.get(sid)
        if entry is None:
            return None
        expires, data = entry
        if expires <= time.monotonic():
            self._data.pop(sid, None)
            return None
        # Copies in/out so callers can't mutate stored state without an explicit
        # set() — the same semantics the JSON round-trip gives the Redis backend.
        return copy.deepcopy(data)

    async def set(self, sid: str, data: dict) -> None:
        self._prune()
        self._data[sid] = (time.monotonic() + self._ttl, copy.deepcopy(data))

    async def delete(self, sid: str) -> None:
        self._data.pop(sid, None)
        lock = self._locks.get(sid)
        if lock is not None and not lock.locked():
            self._locks.pop(sid, None)

    @asynccontextmanager
    async def lock(self, sid: str) -> AsyncIterator[None]:
        lock = self._locks.setdefault(sid, asyncio.Lock())
        async with lock:
            yield


class RedisSessionStore(SessionStore):
    #: A crashed/hung holder can't wedge everyone else: the lock key expires.
    LOCK_TTL = 10

    def __init__(self, url: str, ttl: int, client=None, namespace: str = "tenant") -> None:
        if client is None:
            import redis.asyncio as aioredis  # optional dependency (the "redis" extra)

            client = aioredis.from_url(url, decode_responses=True)
        self._redis = client
        self._ttl = ttl
        # Which deployment these sessions belong to. Without it every BFF pointed at one
        # Redis shares a keyspace, so a provider console and a tenant BFF would resolve
        # each other's session ids — the missing-discriminator shape, one layer out from
        # the plane wall (ADR-0013 §2/§3).
        self._ns = namespace

    def _key(self, sid: str) -> str:
        return f"bff:sess:{self._ns}:{sid}"

    async def get(self, sid: str) -> Optional[dict]:
        raw = await self._redis.get(self._key(sid))
        return json.loads(raw) if raw else None

    async def set(self, sid: str, data: dict) -> None:
        await self._redis.set(self._key(sid), json.dumps(data), ex=self._ttl)

    async def delete(self, sid: str) -> None:
        await self._redis.delete(self._key(sid))

    @asynccontextmanager
    async def lock(self, sid: str) -> AsyncIterator[None]:
        key = f"{self._key(sid)}:lock"
        token = secrets.token_hex(16)
        while not await self._redis.set(key, token, nx=True, ex=self.LOCK_TTL):
            await asyncio.sleep(0.05)
        try:
            yield
        finally:
            # Compare-then-delete without Lua: if the lock expired mid-hold and was
            # re-acquired between the GET and DELETE we could release another
            # holder's lock early — degrading, at worst, to the old concurrent
            # -refresh behaviour, never to a correctness loss.
            if await self._redis.get(key) == token:
                await self._redis.delete(key)

    async def aclose(self) -> None:
        await self._redis.aclose()


# --- request-level helpers ----------------------------------------------------


def _store(request: Request) -> SessionStore:
    return request.app.state.sessions


def current_sid(request: Request) -> Optional[str]:
    sid = request.session.get(COOKIE_SID_KEY)
    return sid if isinstance(sid, str) and sid else None


def cache(request: Request, data: Optional[dict]) -> None:
    """Update this request's cached view (after a store write elsewhere)."""
    request.state._bff_session = data


async def load(request: Request) -> Optional[dict]:
    """The session dict for this request's sid, or None. Cached per request so the
    store is hit once even when several dependencies/handlers ask."""
    cached = getattr(request.state, "_bff_session", _UNSET)
    if cached is not _UNSET:
        return cached
    sid = current_sid(request)
    data = await _store(request).get(sid) if sid else None
    cache(request, data)
    return data


async def establish(request: Request, data: dict) -> str:
    """Create a session for ``data`` and bind it to the cookie.

    Always mints a fresh sid and drops any prior session (cookie cleared first),
    so a pre-login session id can't be fixated."""
    old = current_sid(request)
    if old:
        await _store(request).delete(old)
    sid = secrets.token_urlsafe(32)
    await _store(request).set(sid, data)
    request.session.clear()
    request.session[COOKIE_SID_KEY] = sid
    cache(request, data)
    return sid


async def destroy(request: Request) -> None:
    """End the session: delete the stored state and clear the cookie."""
    sid = current_sid(request)
    if sid:
        await _store(request).delete(sid)
    request.session.clear()
    cache(request, None)
