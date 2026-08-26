# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0013 §2/§3/§5 — the two planes, and the wall between them.

**Written before the implementation, deliberately.** Every property here fails *silently*
if it regresses: the request succeeds, the page renders, and the only symptom is that a
session held authority belonging to the other population. Nothing else in the suite notices.

The gateway learned this lesson one layer down (`tests/test_multi_issuer_isolation.py` in
the gateway repo): the defect was a key missing a discriminator, and it was already there
before anyone looked. The same class applies here, with the same shape — a session, a
scope table, or a cache that does not know which plane it belongs to.

What is being pinned:

* **§3 — plane comes from which IdP authenticated**, never from a request parameter, and is
  never mutated in-session. The two login routes are *structurally* separate for this
  reason: there is no `plane=` input to forget to validate.
* **§5 — `provider:*` are BFF scopes.** They must never appear in a tenant-plane session
  however that tenant's IdP names its groups, and must never be relayed to a gateway as if
  they were gateway scopes.
* **§4 — cross-tenant power is exercised, not held.** A provider session reaching the
  tenant data plane is refused outright (ADR-0017 slice 6 removed the act-on-tenant grant
  that used to lift that refusal, one tenant at a time, for a bounded window; its
  replacement is slice 7, not yet built). What stays pinned here is that unconditional
  refusal — the state every provider session is in right now.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402
from app.security import (  # noqa: E402
    PLANE_PROVIDER,
    PLANE_TENANT,
    PROVIDER_SCOPES,
    provider_scopes_for_groups,
)

TENANT_ISS = "https://tenant-idp.example.com"
PROVIDER_ISS = "https://provider-idp.example.com"
TENANT_ID = "t-1"


@pytest.fixture
def provider_console(monkeypatch):
    """A **provider-console** BFF: the provider IdP, and no tenant IdP.

    Carrying both is refused at startup (see the enforcement tests at the end of this
    file), so this is the topology that will actually exist — and it is still where the
    wall matters. A provider console mounts the same `/api/*` tenant data-plane routes,
    and a shared `SESSION_REDIS_URL` can put a session from either population in front of
    either process. Break-glass password login stays available, which is how the
    tenant-plane cases below are exercised here.
    """
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv(
        "PROVIDER_GROUP_SCOPES",
        '{"provider-sre": "provider:monitor", "provider-support": "provider:admin"}',
    )
    monkeypatch.setenv(
        "PROVIDER_TENANT_REGISTRY",
        f'[{{"tenant_id": "{TENANT_ID}", "display_name": "Tenant One", "gateway_url": "http://t1:8000"}}]',
    )
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _seed_session(client, app, data: dict) -> None:
    """Replace this client's session content, keeping the app's real cookie plumbing.

    A password login mints a real sid and cookie; the stored content is then swapped for
    the session under test. That keeps the cookie/sid path real — a hand-rolled fake
    session would test the fake rather than the wall — while letting these tests be about
    what a session is *allowed to do* once it exists, which outlives any one login route.
    """
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    store = app.state.sessions
    live = getattr(store, "_data", None)
    assert live is not None, "seeding assumes the in-memory store"
    assert len(live) == 1, f"expected exactly one live session, found {len(live)}"
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, dict(data))


# --- §5: provider scopes are BFF scopes, and never a tenant's ------------------


def test_provider_scopes_are_not_gateway_scopes():
    """`provider:*` must never be mistaken for something a gateway understands.

    The gateway's ROLE_SCOPES has no provider entry by design (ADR-0013 §5), so if one of
    these ever leaked into a relayed token request it would be silently dropped rather
    than refused — which is why the separation is asserted here, at the source.
    """
    assert PROVIDER_SCOPES == frozenset({"provider:monitor", "provider:admin"})
    for scope in PROVIDER_SCOPES:
        assert scope.startswith("provider:")
    # No gateway scope is reachable through the provider vocabulary.
    assert not any(s in PROVIDER_SCOPES for s in ("devices:read", "devices:write", "tools:call"))


def test_provider_group_mapping_has_no_fallback():
    """An unmapped group grants nothing — the same rule §6a forced on the gateway.

    A fallback would be the BFF-side twin of the flat `group_roles` escalation: a group
    name the operator never mapped quietly acquiring authority.
    """
    mapping = {"provider-sre": "provider:monitor"}
    assert provider_scopes_for_groups(["provider-sre"], mapping) == frozenset({"provider:monitor"})
    assert provider_scopes_for_groups(["not-mapped"], mapping) == frozenset()
    assert provider_scopes_for_groups([], mapping) == frozenset()


def test_provider_mapping_refuses_a_non_provider_scope():
    """Config cannot map a group to a gateway scope and smuggle it into the provider
    vocabulary — the mapping's range is closed over PROVIDER_SCOPES."""
    with pytest.raises(ValueError, match="provider:"):
        provider_scopes_for_groups(["g"], {"g": "devices:write"})


# --- §3: plane comes from the IdP, not from the request -----------------------


def test_the_two_login_routes_are_structurally_separate(provider_console):
    """There is no `plane=` parameter to validate, because there is no parameter.

    §3 says plane is set from *which IdP authenticated*. Encoding that as a request field
    would put the plane under the caller's control and make every handler responsible for
    re-checking it — the shape of bug this whole file exists to prevent.
    """
    c, app = provider_console
    paths = _route_paths(app)
    assert "/auth/oidc/login" in paths
    assert "/auth/provider/login" in paths
    # And no route carries a plane selector in its path...
    assert not any("plane" in p for p in paths)
    # ...nor in the login body: exactly one field, so there is nothing to smuggle.
    from app.routers.auth import LoginBody

    assert set(LoginBody.model_fields) == {"password"}


def _route_paths(app) -> set[str]:
    """Every registered path, following included routers.

    ``app.routes`` holds opaque wrappers for included routers in this FastAPI version, so
    walking ``original_router`` is what actually enumerates the auth routes.
    """
    out: set[str] = set()
    stack = list(app.routes)
    while stack:
        route = stack.pop()
        path = getattr(route, "path", None)
        if path:
            out.add(path)
        inner = getattr(route, "original_router", None)
        if inner is not None:
            stack.extend(getattr(inner, "routes", []))
    return out


def test_password_login_cannot_request_a_plane(provider_console):
    """Break-glass password login is tenant-plane, full stop. An extra field in the body
    must not move it — a provider console is not reachable with a local password."""
    c, _ = provider_console
    resp = c.post("/auth/login", json={"password": "admin-pw", "plane": PLANE_PROVIDER})
    assert resp.status_code == 200
    me = c.get("/auth/me").json()
    assert me["plane"] == PLANE_TENANT
    assert me.get("provider_scopes", []) == []


def test_me_reports_the_plane_so_the_spa_cannot_guess(provider_console):
    c, _ = provider_console
    c.post("/auth/login", json={"password": "admin-pw"})
    me = c.get("/auth/me").json()
    assert me["plane"] == PLANE_TENANT


# --- §5: a tenant session can never hold provider scopes ----------------------


def test_a_tenant_group_named_like_the_provider_mapping_grants_nothing(provider_console):
    """The BFF-side twin of the gateway's §6a escalation.

    A tenant's own IdP administrator controls their group names. Naming one
    `provider-support` must not reach the provider mapping — which is only true if the
    mapping is consulted for provider-plane logins *only*, never as a shared table.
    """
    c, app = provider_console
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_TENANT,
            "sub": "alice",
            "groups": ["provider-support", "provider-sre"],
            "access_token": "t",
        },
    )
    me = c.get("/auth/me").json()
    assert me["plane"] == PLANE_TENANT
    assert me.get("provider_scopes", []) == [], "tenant session borrowed the provider mapping"


def test_a_provider_session_holds_only_provider_scopes(provider_console):
    c, app = provider_console
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_PROVIDER,
            "sub": "carol",
            "provider_scopes": ["provider:admin"],
            "access_token": "t",
        },
    )
    me = c.get("/auth/me").json()
    assert me["plane"] == PLANE_PROVIDER
    assert me["provider_scopes"] == ["provider:admin"]
    # A provider session carries no tenant-plane authority at all.
    assert me.get("scopes", []) == []


# --- §4: no standing cross-tenant access until a grant exists -----------------


def test_a_provider_session_is_refused_on_the_tenant_data_plane(provider_console):
    """No delegated support grant, no data plane — the state of every provider session that
    has not raised and had a request approved (ADR-0017 §7, slice 7 — the mechanism that
    admits a provider session once it *does* hold one is proven in
    `test_provider_support_requests.py` / `test_tenant_support_requests.py`).
    """
    c, app = provider_console
    called = []

    async def _boom(path, bearer=None):
        called.append(path)
        return httpx.Response(200, json={})

    app.state.gateway.get = _boom
    _seed_session(
        c,
        app,
        {"kind": "oidc", "plane": PLANE_PROVIDER, "sub": "carol", "provider_scopes": ["provider:admin"]},
    )
    for path in ("/api/devices", "/api/overview", "/api/devices/dev/diagnostics"):
        resp = c.get(path)
        assert resp.status_code == 403, f"{path} admitted a provider session"
    assert called == [], "a provider session reached the gateway with no grant"


def test_a_provider_session_holding_a_support_grant_reaches_the_data_plane(provider_console):
    """The positive case: once a delegated support grant is held, the tenant data plane
    relays with *that* credential — never the stack's admin key. And it relays through
    *that tenant's* gateway from the pool (ADR-0021, scoped), never this process's own
    `app.state.gateway` — a provider deployment names no tenant of its own, so that client
    is never the right one for a provider session to use."""
    c, app = provider_console
    seen = []

    async def _ok(path, bearer=None):
        seen.append(bearer)
        return httpx.Response(200, json={"devices": []})

    async def _boom(path, bearer=None):
        raise AssertionError("a provider session's call reached app.state.gateway, not the pool")

    def _pool_get(tenant_id):
        assert tenant_id == TENANT_ID
        return SimpleNamespace(get=_ok)

    app.state.gateway.get = _boom
    app.state.gateway_pool.get = _pool_get
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_PROVIDER,
            "sub": "carol",
            "provider_scopes": ["provider:admin"],
            "support_grant": {"tenant_id": TENANT_ID, "grant_id": "g1", "credential": "sgr_abc123"},
        },
    )

    resp = c.get("/api/devices")

    assert resp.status_code == 200
    assert seen == ["sgr_abc123"]


def test_a_grant_with_no_recorded_tenant_fails_closed_not_silently_to_app_state_gateway(provider_console):
    """A grant shaped by something that predates slice 3 (no `tenant_id`) must not fall
    back to `app.state.gateway` — that client names no tenant in particular on a provider
    deployment, so silently using it would send a tenant-scoped credential somewhere
    unrelated rather than somewhere merely wrong."""
    c, app = provider_console

    async def _boom(path, bearer=None):
        raise AssertionError("app.state.gateway must never be used for a provider session")

    app.state.gateway.get = _boom
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_PROVIDER,
            "sub": "carol",
            "provider_scopes": ["provider:admin"],
            "support_grant": {"grant_id": "g1", "credential": "sgr_abc123"},  # no tenant_id
        },
    )

    resp = c.get("/api/devices")

    assert resp.status_code == 500


def test_a_grant_naming_a_tenant_the_registry_no_longer_has_fails_closed(provider_console):
    c, app = provider_console
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_PROVIDER,
            "sub": "carol",
            "provider_scopes": ["provider:admin"],
            "support_grant": {"tenant_id": "gone", "grant_id": "g1", "credential": "sgr_abc123"},
        },
    )

    resp = c.get("/api/devices")

    assert resp.status_code == 500


def test_a_401d_support_grant_is_cleared_from_the_session(provider_console):
    """The gateway checks a support grant live on every request — a 401 means it is
    genuinely gone (revoked or expired), not a caching problem the BFF should paper over.
    Clearing it is what makes the *next* read honestly report no grant held, rather than a
    phantom stale one (`relay._drop_dead_support_grant`)."""
    c, app = provider_console

    async def _dead(path, bearer=None):
        return httpx.Response(401, json={"detail": "invalid or missing token"})

    app.state.gateway_pool.get = lambda tenant_id: SimpleNamespace(get=_dead)
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_PROVIDER,
            "sub": "carol",
            "provider_scopes": ["provider:admin"],
            "support_grant": {"tenant_id": TENANT_ID, "grant_id": "g1", "credential": "sgr_stale"},
        },
    )

    resp = c.get("/api/devices")
    assert resp.status_code == 401

    live = app.state.sessions._data
    sid = next(iter(live))
    _, stored = live[sid]
    assert "support_grant" not in stored


def test_a_tenant_session_still_works_unchanged(provider_console):
    """The control. Without it the refusal above would pass on an implementation that
    simply refuses everyone."""
    c, app = provider_console

    async def _ok(path, bearer=None):
        return httpx.Response(200, json={"mode": "embedded", "counts": {}, "devices": []})

    app.state.gateway.get = _ok
    c.post("/auth/login", json={"password": "admin-pw"})
    assert c.get("/api/overview").status_code == 200


# --- The discriminator lesson, applied to the BFF's own state -----------------


def test_same_subject_on_two_planes_is_two_distinct_sessions(provider_console):
    """`sub` is unique within an IdP, not across them.

    The gateway hit exactly this (`oidc:{sub}` conflating two humans in one audit line).
    Any BFF state keyed on the subject — session, cache, throttle, audit actor — has to
    carry the plane too, or the two populations merge without a symptom.
    """
    c, app = provider_console
    from app.security import session_identity

    tenant = {"kind": "oidc", "plane": PLANE_TENANT, "sub": "admin"}
    provider = {"kind": "oidc", "plane": PLANE_PROVIDER, "sub": "admin"}
    assert session_identity(tenant) != session_identity(provider)
    assert PLANE_TENANT in session_identity(tenant)
    assert PLANE_PROVIDER in session_identity(provider)


# --- Gaps found by mutation, each closing a surviving mutant ------------------


def test_a_session_with_no_plane_reads_as_tenant(provider_console):
    """The fail-safe direction, asserted rather than assumed.

    Sessions written before the provider plane existed carry no `plane` key, and so does
    anything that forgets to set one. Defaulting such a session to *provider* would hand
    cross-tenant standing to every legacy session at once — silently, since they would
    keep working. Tenant is the plane with no cross-tenant authority, so it is the only
    safe default.

    Found by mutation: flipping the default changed no test result.
    """
    from app.security import session_plane

    c, app = provider_console
    assert session_plane({"kind": "oidc", "sub": "alice"}) == PLANE_TENANT
    assert session_plane({}) == PLANE_TENANT
    assert session_plane(None) == PLANE_TENANT
    # An unrecognised value is not trusted either — no "unknown plane" third state.
    assert session_plane({"plane": "provider-ish"}) == PLANE_TENANT

    _seed_session(c, app, {"kind": "oidc", "sub": "alice", "access_token": "t"})
    assert c.get("/auth/me").json()["plane"] == PLANE_TENANT


def test_a_retired_scope_is_refused_as_unknown():
    """`provider:invoke` (ADR-0017 slice 6) and `provider:credentials` (ADR-0018 §6) were
    both time-boxed elevated grants — the only class that ever needed a *distinct* refusal
    from an ordinary unmapped scope, since the elevation mechanism used to special-case them.
    That mechanism is gone: a group mapping naming either now fails the same way naming a
    typo would, and this asserts they collapse into the one generic refusal rather than
    silently succeeding now that nothing recognizes them as special."""
    for retired in ("provider:invoke", "provider:credentials"):
        with pytest.raises(ValueError, match="not one of"):
            provider_scopes_for_groups(["sre"], {"sre": retired})
    # The everyday grant is still mappable.
    assert provider_scopes_for_groups(["sre"], {"sre": "provider:admin"}) == frozenset({"provider:admin"})


def test_a_tenant_session_is_refused_on_a_provider_route(provider_console):
    """The converse refusal, which an implementation can easily get one-sided.

    Slice 1 ships no provider routes yet, so the dependency is exercised directly through
    a mounted probe — otherwise the guard is untested until slice 2 adds the first caller,
    which is the wrong order for a wall.

    Found by mutation: disabling the provider-plane check broke nothing.
    """
    from fastapi import Depends

    from app.security import require_provider_scope

    c, app = provider_console

    @app.get("/test/provider-only", dependencies=[Depends(require_provider_scope("provider:admin"))])
    async def _probe():  # pragma: no cover - the dependency is the subject
        return {"ok": True}

    # A tenant session that *holds the required scope*. This is the case that isolates the
    # plane check: an empty-scoped tenant session would be refused by the scope check
    # instead, masking the removal of the plane check entirely (the second mutant to hide
    # behind a downstream backstop this way).
    _seed_session(
        c,
        app,
        {"kind": "oidc", "plane": PLANE_TENANT, "sub": "alice", "provider_scopes": ["provider:admin"]},
    )
    assert c.get("/test/provider-only").status_code == 403, "plane check bypassed by a contaminated session"

    # A plain tenant session is refused too, for whichever reason comes first.
    _seed_session(c, app, {"kind": "oidc", "plane": PLANE_TENANT, "sub": "alice"})
    assert c.get("/test/provider-only").status_code == 403

    # A provider session without the scope is refused too.
    _seed_session(c, app, {"kind": "oidc", "plane": PLANE_PROVIDER, "sub": "carol", "provider_scopes": []})
    assert c.get("/test/provider-only").status_code == 403

    # ...and with it, admitted. Without this the two above would pass on a guard that
    # refuses everyone.
    _seed_session(
        c, app, {"kind": "oidc", "plane": PLANE_PROVIDER, "sub": "carol", "provider_scopes": ["provider:admin"]}
    )
    assert c.get("/test/provider-only").status_code == 200


def test_provider_scopes_on_a_tenant_session_are_not_reported(provider_console):
    """A contaminated tenant session must still report no provider authority.

    Found by mutation, and it was the *fixture starting past the bug* again: every tenant
    session in this file had no `provider_scopes` key, so reporting them changed nothing.
    Here the key is present and populated — the state a bug would actually produce — and
    `/auth/me` must still say the tenant plane holds none of it.
    """
    c, app = provider_console
    _seed_session(
        c,
        app,
        {
            "kind": "oidc",
            "plane": PLANE_TENANT,
            "sub": "alice",
            "access_token": "t",
            "provider_scopes": ["provider:admin", "provider:invoke"],
        },
    )
    me = c.get("/auth/me").json()
    assert me["plane"] == PLANE_TENANT
    assert me["provider_scopes"] == [], "a tenant session reported provider authority"


# --- The preference, enforced rather than documented -------------------------


def test_configuring_both_idps_refuses_to_start(monkeypatch):
    """A tenant-stack BFF must not carry the provider IdP — enforced, not advised.

    The whole argument in ADR-0013 §11 was that a bound living outside enforcement is not
    a bound; a README paragraph is exactly that. So the combination fails closed at
    startup, in the same shape as the gateway's `trust_proxy_headers`-without-CIDRs
    refusal: the operator is told at boot, not after an incident.
    """
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER", TENANT_ISS)
    monkeypatch.setenv("OIDC_CLIENT_ID", "tenant-ui")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://ui.example.com/auth/oidc/callback")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    with pytest.raises(RuntimeError, match="tenant"):
        create_app()


def test_each_plane_alone_starts_fine(monkeypatch):
    """The control — the refusal is about the *combination*, not about either IdP."""
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER", TENANT_ISS)
    monkeypatch.setenv("OIDC_CLIENT_ID", "tenant-ui")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://ui.example.com/auth/oidc/callback")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "false")
    tenant_app = create_app()
    assert tenant_app.state.provider_oidc is None

    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    provider_app = create_app()
    assert provider_app.state.provider_oidc is not None
    assert provider_app.state.oidc is None


def test_session_keys_are_namespaced_per_deployment():
    """Two BFFs sharing one SESSION_REDIS_URL must not share a session namespace.

    This is the leak the startup refusal *cannot* reach: it is per-process, and the store
    is not. `bff:sess:{sid}` put every deployment in one keyspace, so a provider console
    and a tenant BFF pointed at the same Redis would resolve each other's session ids —
    the missing-discriminator shape again, one layer out.

    The plane wall still holds if it happens (a provider session is refused on the tenant
    data plane whichever process loaded it), which is exactly why the wall is kept as well
    as the refusal rather than instead of it.
    """
    from app.sessions import RedisSessionStore

    tenant = RedisSessionStore("redis://x", ttl=60, client=object(), namespace="tenant:acme")
    provider = RedisSessionStore("redis://x", ttl=60, client=object(), namespace="provider")
    assert tenant._key("abc") != provider._key("abc")
    assert "acme" in tenant._key("abc")
    assert "provider" in provider._key("abc")
