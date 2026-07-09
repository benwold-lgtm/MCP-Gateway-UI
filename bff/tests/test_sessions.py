# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Server-side session store: backend behaviour + the concurrent-refresh guarantee.

The whole point of moving sessions out of the cookie (review Batch D) is (1) tokens
never reach the browser and (2) OIDC refresh can be serialised per session. The
tests here pin both: store semantics for each backend, and that two requests racing
one expired access token perform exactly one IdP refresh.
"""

import asyncio
import os

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.main import create_app  # noqa: E402
from app.sessions import MemorySessionStore, RedisSessionStore  # noqa: E402

# --- MemorySessionStore --------------------------------------------------------


async def test_memory_roundtrip_and_delete():
    store = MemorySessionStore(ttl=60)
    await store.set("sid1", {"kind": "password", "role": "admin"})
    assert await store.get("sid1") == {"kind": "password", "role": "admin"}
    await store.delete("sid1")
    assert await store.get("sid1") is None
    assert await store.get("never-stored") is None


async def test_memory_ttl_expiry(monkeypatch):
    from app import sessions as mod

    clock = {"t": 1000.0}
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock["t"])
    store = MemorySessionStore(ttl=60)
    await store.set("sid1", {"kind": "password", "role": "admin"})
    clock["t"] += 59
    assert await store.get("sid1") is not None
    clock["t"] += 2  # past the TTL
    assert await store.get("sid1") is None
    # set() prunes: the expired entry is gone from the backing dict, not just masked.
    await store.set("sid2", {"kind": "password", "role": "viewer"})
    assert "sid1" not in store._data


async def test_memory_returns_copies():
    """Callers can't mutate stored state without an explicit set() — matches the
    JSON round-trip semantics of the Redis backend."""
    store = MemorySessionStore(ttl=60)
    await store.set("sid1", {"kind": "oidc", "access_token": "a"})
    view = await store.get("sid1")
    view["access_token"] = "tampered"
    assert (await store.get("sid1"))["access_token"] == "a"


async def test_memory_lock_serialises():
    store = MemorySessionStore(ttl=60)
    order = []

    async def critical(tag):
        async with store.lock("sid1"):
            order.append(f"{tag}-in")
            await asyncio.sleep(0.01)
            order.append(f"{tag}-out")

    await asyncio.gather(critical("a"), critical("b"))
    # Never interleaved: each holder exits before the next enters.
    assert order in (["a-in", "a-out", "b-in", "b-out"], ["b-in", "b-out", "a-in", "a-out"])


# --- RedisSessionStore (against fakeredis) --------------------------------------


@pytest.fixture
def redis_store():
    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return RedisSessionStore("redis://unused", ttl=60, client=client)


async def test_redis_roundtrip_and_delete(redis_store):
    await redis_store.set("sid1", {"kind": "oidc", "access_token": "a", "sub": "alice"})
    assert await redis_store.get("sid1") == {"kind": "oidc", "access_token": "a", "sub": "alice"}
    await redis_store.delete("sid1")
    assert await redis_store.get("sid1") is None


async def test_redis_sets_ttl(redis_store):
    await redis_store.set("sid1", {"kind": "password", "role": "admin"})
    ttl = await redis_store._redis.ttl("bff:sess:sid1")
    assert 0 < ttl <= 60


async def test_redis_lock_serialises(redis_store):
    order = []

    async def critical(tag):
        async with redis_store.lock("sid1"):
            order.append(f"{tag}-in")
            await asyncio.sleep(0.01)
            order.append(f"{tag}-out")

    await asyncio.gather(critical("a"), critical("b"))
    assert order in (["a-in", "a-out", "b-in", "b-out"], ["b-in", "b-out", "a-in", "a-out"])
    # The lock key is released afterwards.
    assert await redis_store._redis.get("bff:sess:sid1:lock") is None


# --- Concurrent OIDC refresh through the app (the race the store exists to fix) --


class _RacingOIDC:
    """IdP stub whose refresh is slow enough that unserialised callers would overlap."""

    USER_TOKEN = "user-access-token"

    def __init__(self):
        self.refreshes = 0

    async def authorization_url(self, *, state, nonce, challenge):
        return f"https://idp.example/authorize?state={state}"

    async def exchange_code(self, *, code, verifier):
        return {"id_token": "id.tok.sig", "access_token": self.USER_TOKEN, "refresh_token": "refresh-1"}

    async def validate_id_token(self, *, id_token, nonce, access_token=None):
        return {"sub": "alice", "name": "Alice", "nonce": nonce}

    async def refresh_tokens(self, *, refresh_token):
        self.refreshes += 1
        n = self.refreshes
        await asyncio.sleep(0.05)  # both racers are in-flight before the first finishes
        # Rotation: each refresh invalidates the token it consumed, like a strict IdP.
        return {"access_token": f"refreshed-{n}", "refresh_token": f"refresh-{n + 1}"}


async def test_concurrent_401s_refresh_exactly_once():
    """Two simultaneous relayed calls hitting an expired access token must produce ONE
    IdP refresh — the loser of the lock race reuses the winner's rotated tokens. With
    the old cookie-based session this raced and could invalidate a rotated token."""
    app = create_app()
    oidc = _RacingOIDC()
    app.state.oidc = oidc
    accepted = set()

    async def _gw_get(path, bearer=None):
        if path == "/auth/me":  # login-time whoami
            return httpx.Response(200, json={"subject": "oidc:alice", "scopes": []})
        if bearer == _RacingOIDC.USER_TOKEN:
            return httpx.Response(401, json={"detail": "token expired"})
        accepted.add(bearer)
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _gw_get

    from urllib.parse import parse_qs, urlparse

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bff") as c:
        r = await c.get("/auth/oidc/login", follow_redirects=False)
        state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
        cb = await c.get(f"/auth/oidc/callback?code=abc&state={state}", follow_redirects=False)
        assert cb.status_code == 302

        r1, r2 = await asyncio.gather(c.get("/api/devices"), c.get("/api/devices"))

    assert r1.status_code == 200 and r2.status_code == 200
    assert oidc.refreshes == 1  # serialised: the second request reused the first's token
    assert accepted == {"refreshed-1"}
