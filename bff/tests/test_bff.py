# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""BFF behaviour: login/session, auth gating, role gating, and gateway passthrough."""

import os

os.environ["UI_ADMIN_PASSWORD"] = "admin-pw"
os.environ["UI_VIEWER_PASSWORD"] = "viewer-pw"
os.environ["SESSION_SECRET"] = "test-secret"

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.audit import verify_chain  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def app_client():
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _fake_get(payload, status=200):
    async def _g(path, bearer=None):
        return httpx.Response(status, json=payload)

    return _g


def _fake_request(payload, status=200):
    async def _r(method, path, json=None, bearer=None, headers=None):
        return httpx.Response(status, json=payload)

    return _r


def test_healthz(app_client):
    c, _ = app_client
    assert c.get("/healthz").json() == {"status": "ok"}


def test_login_rejects_bad_password(app_client):
    c, _ = app_client
    assert c.post("/auth/login", json={"password": "nope"}).status_code == 401


def test_login_sets_role_and_me(app_client):
    c, _ = app_client
    assert c.post("/auth/login", json={"password": "admin-pw"}).json() == {"role": "admin"}
    me = c.get("/auth/me").json()
    assert me["kind"] == "password" and me["role"] == "admin"
    # Admin's break-glass bundle gates the UI; devices:write enables the write affordances.
    assert "devices:write" in me["scopes"]


def test_me_scopes_for_viewer_are_read_only(app_client):
    c, _ = app_client
    c.post("/auth/login", json={"password": "viewer-pw"})
    me = c.get("/auth/me").json()
    assert me["role"] == "viewer"
    assert "devices:write" not in me["scopes"] and "devices:read" in me["scopes"]


def test_api_requires_session(app_client):
    c, _ = app_client
    assert c.get("/api/overview").status_code == 401


def test_overview_proxies_gateway(app_client):
    c, app = app_client
    app.state.gateway.get = _fake_get({"mode": "embedded", "counts": {}, "devices": []})
    c.post("/auth/login", json={"password": "viewer-pw"})
    resp = c.get("/api/overview")
    assert resp.status_code == 200
    assert resp.json()["mode"] == "embedded"


def test_overview_passes_device_fields_through_untouched(app_client):
    """Guard for gateway ADR-0018 §3, and for every field the gateway adds after it.

    `credential_state` marks a device that is registered and reachable and cannot
    authenticate — restored from an archive without its OAuth2 refresh token, which archives
    never carry. The console reads it off the fleet list, so if this route ever grows a
    `response_model`, Pydantic would drop the field as unknown and the whole feature would
    disappear from the UI **silently**: no error, no 500, just a device that looks fine.

    Asserted as passthrough of an arbitrary field rather than of this one specifically,
    because the next field the gateway adds deserves the same protection without anybody
    remembering to extend this test.
    """
    c, app = app_client
    app.state.gateway.get = _fake_get(
        {
            "mode": "embedded",
            "counts": {},
            "devices": [{"hostname": "rotator", "credential_state": "needs_reconnect", "future_field": 7}],
        }
    )
    c.post("/auth/login", json={"password": "viewer-pw"})

    device = c.get("/api/overview").json()["devices"][0]
    assert device["credential_state"] == "needs_reconnect"
    assert device["future_field"] == 7, "the BFF must not model-filter the gateway's device shape"


def _capture_get(seen, payload, status=200):
    async def _g(path, bearer=None):
        seen.append(path)
        return httpx.Response(status, json=payload)

    return _g


def test_diagnostics_proxies_gateway(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.get = _capture_get(seen, {"hostname": "dev", "reachable": True, "breaker": {"available": False}})
    c.post("/auth/login", json={"password": "viewer-pw"})
    resp = c.get("/api/devices/dev/diagnostics")
    assert resp.status_code == 200
    assert resp.json()["hostname"] == "dev"
    # The router must hit the gateway's per-device diagnostics path.
    assert seen == ["/devices/dev/diagnostics"]


def test_tools_proxies_gateway(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.get = _capture_get(seen, {"hostname": "dev", "tools": [{"name": "t"}], "count": 1})
    c.post("/auth/login", json={"password": "viewer-pw"})
    resp = c.get("/api/devices/dev/tools")
    assert resp.json()["count"] == 1
    assert seen == ["/devices/dev/tools"]


def test_tools_diff_proxies_gateway(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.get = _capture_get(seen, {"hostname": "dev", "tools_revision": 2, "last_change": None})
    c.post("/auth/login", json={"password": "viewer-pw"})
    resp = c.get("/api/devices/dev/tools/diff")
    assert resp.status_code == 200
    assert resp.json()["tools_revision"] == 2
    assert seen == ["/devices/dev/tools/diff"]


def test_device_reads_require_session(app_client):
    c, _ = app_client
    assert c.get("/api/devices/dev/diagnostics").status_code == 401
    assert c.get("/api/devices/dev/tools").status_code == 401
    assert c.get("/api/devices/dev/tools/diff").status_code == 401


def test_viewer_cannot_mutate(app_client):
    c, app = app_client
    app.state.gateway.request = _fake_request({"status": "registered"})
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.post("/api/devices", json={"hostname": "x", "base_url": "http://x"}).status_code == 403


def test_admin_can_register(app_client):
    c, app = app_client
    app.state.gateway.request = _fake_request({"status": "registered"}, status=200)
    c.post("/auth/login", json={"password": "admin-pw"})
    resp = c.post("/api/devices", json={"hostname": "x", "base_url": "http://x"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "registered"


def _capture_request(seen, payload, status=200):
    async def _r(method, path, json=None, bearer=None, headers=None):
        seen.append((method, path, json))
        return httpx.Response(status, json=payload)

    return _r


def test_admin_can_update(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.request = _capture_request(seen, {"status": "registered", "hostname": "x"})
    c.post("/auth/login", json={"password": "admin-pw"})
    resp = c.put("/api/devices/x", json={"base_url": "http://new"})
    assert resp.status_code == 200
    # The router proxies a PUT to the gateway's device path, body passed through.
    assert seen == [("PUT", "/devices/x", {"base_url": "http://new"})]


def test_viewer_cannot_update(app_client):
    c, app = app_client
    app.state.gateway.request = _fake_request({"status": "ok"})
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.put("/api/devices/x", json={"base_url": "http://new"}).status_code == 403


def test_deadletter_list_proxies_gateway(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.get = _capture_get(seen, {"hostname": "dev", "count": 0, "entries": []})
    c.post("/auth/login", json={"password": "viewer-pw"})
    resp = c.get("/api/devices/dev/deadletter")
    assert resp.status_code == 200
    assert seen == ["/devices/dev/deadletter"]


def test_deadletter_replay_admin_only(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.request = _capture_request(seen, {"hostname": "dev", "replayed": 2})
    # viewer is refused before any upstream call
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.post("/api/devices/dev/deadletter/replay", json={"ids": ["1-0"]}).status_code == 403
    assert seen == []
    # admin replays specific ids — body passed through
    c.post("/auth/login", json={"password": "admin-pw"})
    resp = c.post("/api/devices/dev/deadletter/replay", json={"ids": ["1-0"]})
    assert resp.json()["replayed"] == 2
    assert seen == [("POST", "/devices/dev/deadletter/replay", {"ids": ["1-0"]})]


def test_deadletter_drain_admin_only(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.request = _capture_request(seen, {"hostname": "dev", "removed": 5})
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.delete("/api/devices/dev/deadletter").status_code == 403
    c.post("/auth/login", json={"password": "admin-pw"})
    resp = c.delete("/api/devices/dev/deadletter")
    assert resp.json()["removed"] == 5
    # No body → drain the whole queue (json=None forwarded).
    assert seen == [("DELETE", "/devices/dev/deadletter", None)]


# --- Endpoint fingerprint approval (gateway ADR-0015 §6) ----------------------


@pytest.fixture
def audited_client(tmp_path, monkeypatch):
    """An app whose audit log actually writes to a file.

    The default fixture leaves AUDIT_PATH empty, so records chain but land nowhere and
    `read()` returns nothing. Approval is a *trust decision* — the claim that it is
    audited is only worth testing against the real writer, so this fixture gives it one.
    """
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    app = create_app()
    with TestClient(app) as c:
        yield c, app, tmp_path / "audit.log"


def test_fingerprint_approve_is_admin_only(app_client):
    c, app = app_client
    seen = []
    app.state.gateway.request = _capture_request(seen, {"status": "fingerprint_approved"})
    # A viewer is refused here, not upstream: the gateway must never see the call.
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.post("/api/devices/dev/fingerprint/approve").status_code == 403
    assert seen == []

    c.post("/auth/login", json={"password": "admin-pw"})
    resp = c.post("/api/devices/dev/fingerprint/approve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "fingerprint_approved"
    # POST with no body — the gateway's approve endpoint takes none.
    assert seen == [("POST", "/devices/dev/fingerprint/approve", None)]


def test_fingerprint_approve_requires_a_session(app_client):
    c, _ = app_client
    assert c.post("/api/devices/dev/fingerprint/approve").status_code == 401


def test_fingerprint_approve_passes_the_gateway_409_through(app_client):
    """Approving a device that is not pending must fail visibly.

    The gateway 409s when the state moved on (someone else approved, or the device was
    re-probed) — the operator is acting on a stale screen, and turning that into a 200
    would tell them a trust decision succeeded when it did not.
    """
    c, app = app_client
    app.state.gateway.request = _fake_request({"detail": "no fingerprint change awaiting approval"}, status=409)
    c.post("/auth/login", json={"password": "admin-pw"})
    resp = c.post("/api/devices/dev/fingerprint/approve")
    assert resp.status_code == 409
    assert "awaiting approval" in resp.json()["detail"]


def test_fingerprint_approve_is_audited(audited_client):
    c, app, path = audited_client
    app.state.gateway.request = _fake_request({"status": "fingerprint_approved"})
    c.post("/auth/login", json={"password": "admin-pw"})
    assert c.post("/api/devices/dev/fingerprint/approve").status_code == 200

    # The same action name the gateway uses, so the two chains describe one event.
    approvals = [r["content"] for r in app.state.audit.read() if r["content"]["action"] == "device.fingerprint.approve"]
    assert len(approvals) == 1, "approval wrote no audit record (or wrote it twice)"
    assert approvals[0]["target"] == "dev"
    assert approvals[0]["outcome"] == "success"
    ok, detail = verify_chain(path)
    assert ok, detail


def test_fingerprint_approve_audits_a_refusal_as_denied(audited_client):
    """A rejected approval is the record an incident actually asks for.

    403 maps to `denied` rather than a generic error precisely so "who was refused what"
    survives in the log.
    """
    c, app, _ = audited_client
    app.state.gateway.request = _fake_request({"detail": "forbidden"}, status=403)
    c.post("/auth/login", json={"password": "admin-pw"})
    assert c.post("/api/devices/dev/fingerprint/approve").status_code == 403

    approvals = [r["content"] for r in app.state.audit.read() if r["content"]["action"] == "device.fingerprint.approve"]
    assert len(approvals) == 1
    assert approvals[0]["outcome"] == "denied"


def test_viewer_refusal_is_not_audited_by_the_bff(audited_client):
    """A viewer never reaches the audited handler — the role dependency refuses first.

    Asserted so the gap is a recorded decision rather than a surprise: the BFF's chain
    covers *attempted mutations that got as far as the gateway*, and role refusals are
    the session layer's business.
    """
    c, app, _ = audited_client
    app.state.gateway.request = _fake_request({"status": "fingerprint_approved"})
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.post("/api/devices/dev/fingerprint/approve").status_code == 403
    # The login itself is audited, so filter rather than asserting an empty log.
    actions = [r["content"]["action"] for r in app.state.audit.read()]
    assert "device.fingerprint.approve" not in actions


def test_monitoring_meta_reports_unconfigured_by_default(app_client):
    c, _ = app_client
    c.post("/auth/login", json={"password": "viewer-pw"})
    body = c.get("/api/monitoring/meta").json()
    # Default test env sets no PROMETHEUS_URL / LOKI_URL / GRAFANA_URL.
    assert body == {"prometheus_enabled": False, "loki_enabled": False, "grafana_url": None}


def test_monitoring_meta_requires_session(app_client):
    c, _ = app_client
    assert c.get("/api/monitoring/meta").status_code == 401


def test_prometheus_and_logs_501_when_unconfigured(app_client):
    c, _ = app_client
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.get("/api/prometheus/query", params={"query": "up"}).status_code == 501
    assert c.get("/api/logs").status_code == 501


def test_logout_clears_session(app_client):
    c, _ = app_client
    c.post("/auth/login", json={"password": "admin-pw"})
    c.post("/auth/logout")
    assert c.get("/auth/me").status_code == 401


def test_gateway_calls_are_v1_prefixed():
    """Regression guard: the gateway mounts its management API under /v1, so every
    upstream call the BFF makes must carry that prefix (the bug that left the BFF
    hitting unversioned paths and 404ing on a live gateway)."""
    from app.config import load_settings
    from app.gateway_client import GatewayClient

    client = GatewayClient(load_settings())
    assert client._with_prefix("/admin/overview") == "/v1/admin/overview"
    assert client._with_prefix("devices") == "/v1/devices"
    assert client._with_prefix("/devices/my-host") == "/v1/devices/my-host"


def test_gateway_prefix_is_configurable(monkeypatch):
    """A future gateway version (e.g. /v2) is a one-env-var change, no code edits."""
    from app.config import load_settings
    from app.gateway_client import GatewayClient

    monkeypatch.setenv("GATEWAY_API_PREFIX", "/v2")
    client = GatewayClient(load_settings())
    assert client._with_prefix("/devices") == "/v2/devices"


# --- OIDC login (Authorization Code + PKCE) + per-user relay (ADR-0007) -------
#
# A stub Relying Party stands in for the IdP so the suite stays offline. It echoes the
# real state/nonce so the test can drive the callback, and returns a fixed access token
# whose presence on the upstream call proves the token-passthrough relay.


from urllib.parse import parse_qs, urlparse  # noqa: E402


class _FakeOIDC:
    USER_TOKEN = "user-access-token"
    REFRESH_TOKEN = "refresh-tok-1"
    REFRESHED_TOKEN = "refreshed-access-token"
    ROTATED_REFRESH = "refresh-tok-2"

    def __init__(self):
        self.last = {}
        self.refreshes = 0

    async def authorization_url(self, *, state, nonce, challenge):
        self.last = {"state": state, "nonce": nonce, "challenge": challenge}
        return f"https://idp.example/authorize?{urlencode_min(state=state, nonce=nonce)}"

    async def exchange_code(self, *, code, verifier):
        self.last["code"] = code
        self.last["verifier"] = verifier
        return {"id_token": "id.tok.sig", "access_token": self.USER_TOKEN, "refresh_token": self.REFRESH_TOKEN}

    async def refresh_tokens(self, *, refresh_token):
        self.refreshes += 1
        self.last["refresh_used"] = refresh_token
        return {"access_token": self.REFRESHED_TOKEN, "refresh_token": self.ROTATED_REFRESH}

    async def validate_id_token(self, *, id_token, nonce, access_token=None):
        self.last["validated_access_token"] = access_token
        return {"sub": "alice", "name": "Alice", "nonce": nonce}

    async def end_session_url(self, *, id_token_hint, post_logout_redirect_uri=None):
        self.last["id_token_hint"] = id_token_hint
        url = f"https://idp.example/logout?id_token_hint={id_token_hint}"
        if post_logout_redirect_uri:
            url += f"&post_logout_redirect_uri={post_logout_redirect_uri}"
        return url


def urlencode_min(**kw):
    return "&".join(f"{k}={v}" for k, v in kw.items())


@pytest.fixture
def oidc_client():
    app = create_app()
    app.state.oidc = _FakeOIDC()
    with TestClient(app) as c:
        yield c, app


def _do_oidc_login(c):
    """Drive the redirect → callback handshake; returns the established TestClient."""
    r = c.get("/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    cb = c.get(f"/auth/oidc/callback?code=abc&state={state}", follow_redirects=False)
    assert cb.status_code == 302
    return cb


def test_auth_config_reports_methods(app_client):
    """Exact equality on purpose: this is what the SPA branches its whole shell on, so a
    field appearing or vanishing should fail here rather than change a console silently."""
    c, _ = app_client
    body = c.get("/auth/config").json()
    assert body == {
        "oidc_enabled": False,
        "password_login": True,
        # A plain tenant-stack BFF. `provider_enabled` false is what makes the SPA render
        # the tenant login rather than the provider one (ADR-0013 §2/§5).
        "provider_enabled": False,
    }


def test_oidc_config_enabled_when_rp_present(oidc_client):
    c, _ = oidc_client
    assert c.get("/auth/config").json()["oidc_enabled"] is True


def test_oidc_login_redirects_with_state_and_pkce(oidc_client):
    c, app = oidc_client
    r = c.get("/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302
    # The RP received a state, nonce, and S256 challenge.
    assert app.state.oidc.last["state"] and app.state.oidc.last["nonce"] and app.state.oidc.last["challenge"]


def test_oidc_callback_state_mismatch_rejected(oidc_client):
    c, _ = oidc_client
    c.get("/auth/oidc/login", follow_redirects=False)  # seeds oidc_tx
    bad = c.get("/auth/oidc/callback?code=abc&state=forged", follow_redirects=False)
    assert bad.status_code == 400


def test_oidc_callback_without_tx_rejected(oidc_client):
    c, _ = oidc_client  # no prior /login → no oidc_tx in session
    r = c.get("/auth/oidc/callback?code=abc&state=whatever", follow_redirects=False)
    assert r.status_code == 400


def test_oidc_login_establishes_session(oidc_client):
    c, app = oidc_client

    async def _g(path, bearer=None):
        # The BFF relays the user token to the gateway whoami for scopes.
        assert path == "/auth/me" and bearer == _FakeOIDC.USER_TOKEN
        return httpx.Response(200, json={"subject": "oidc:alice", "scopes": ["devices:read"], "auth_method": "oidc"})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    me = c.get("/auth/me").json()
    assert me["kind"] == "oidc" and me["subject"] == "oidc:alice" and me["role"] is None
    # Scopes come straight from the gateway — the UI gates on the gateway's grant.
    assert me["scopes"] == ["devices:read"]


def test_oidc_me_clears_session_when_gateway_401s(oidc_client):
    c, app = oidc_client

    async def _g(path, bearer=None):
        return httpx.Response(401, json={"detail": "Unauthorized"})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    # Gateway rejects the relayed token → the BFF ends the session.
    assert c.get("/auth/me").status_code == 401
    assert c.get("/auth/me").status_code == 401  # session is gone


def test_oidc_session_relays_user_token_upstream(oidc_client):
    c, app = oidc_client
    seen = []

    async def _g(path, bearer=None):
        seen.append((path, bearer))
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    assert c.get("/api/devices").status_code == 200
    # The relay forwarded the user's access token, not the admin token (None here).
    assert seen == [("/devices", _FakeOIDC.USER_TOKEN)]


def test_oidc_session_authz_delegated_to_gateway(oidc_client):
    """An OIDC session is not re-authorized at the BFF — a mutation passes the BFF role
    gate (the gateway decides on the user's real scopes)."""
    c, app = oidc_client
    seen = []

    async def _r(method, path, json=None, bearer=None, headers=None):
        seen.append((method, path, bearer))
        return httpx.Response(200, json={"status": "registered"})

    app.state.gateway.request = _r
    _do_oidc_login(c)
    resp = c.post("/api/devices", json={"hostname": "x", "base_url": "http://x"})
    assert resp.status_code == 200
    assert seen == [("POST", "/devices", _FakeOIDC.USER_TOKEN)]


def test_password_session_does_not_relay_user_token(app_client):
    """A local password session uses the admin token (bearer=None at the call site)."""
    c, app = app_client
    seen = []

    async def _g(path, bearer=None):
        seen.append((path, bearer))
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _g
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.get("/api/devices").status_code == 200
    assert seen == [("/devices", None)]


def test_oidc_logout_returns_end_session_url(oidc_client):
    """RP-initiated logout: an OIDC session's logout hands back the IdP end-session URL
    (with the id_token as id_token_hint) so the SPA can end the IdP session too."""
    c, app = oidc_client

    async def _g(path, bearer=None):
        return httpx.Response(200, json={"subject": "oidc:alice", "scopes": ["devices:read"]})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    body = c.post("/auth/logout").json()
    assert body["status"] == "logged out"
    assert body["end_session_url"].startswith("https://idp.example/logout?id_token_hint=id.tok.sig")
    # Session is gone afterwards.
    assert c.get("/auth/me").status_code == 401


def test_password_logout_has_no_end_session_url(app_client):
    c, _ = app_client
    c.post("/auth/login", json={"password": "admin-pw"})
    body = c.post("/auth/logout").json()
    assert body == {"status": "logged out", "end_session_url": None}


def test_oidc_callback_passes_access_token_for_at_hash(oidc_client):
    """The callback hands the access token to validate_id_token so at_hash can bind them."""
    c, app = oidc_client

    async def _g(path, bearer=None):
        return httpx.Response(200, json={"subject": "oidc:alice", "scopes": []})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    assert app.state.oidc.last["validated_access_token"] == _FakeOIDC.USER_TOKEN


# --- Hardening follow-ups (session secret, log cap, at_hash) ------------------


def test_create_app_refuses_default_secret_under_tls(monkeypatch):
    from app.config import DEFAULT_SESSION_SECRET

    monkeypatch.setenv("SESSION_SECRET", DEFAULT_SESSION_SECRET)
    monkeypatch.setenv("COOKIE_SECURE", "true")
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        create_app()


def test_create_app_allows_default_secret_without_tls(monkeypatch):
    from app.config import DEFAULT_SESSION_SECRET

    monkeypatch.setenv("SESSION_SECRET", DEFAULT_SESSION_SECRET)
    monkeypatch.setenv("COOKIE_SECURE", "false")
    create_app()  # dev convenience: no TLS → default secret tolerated


def test_logs_limit_is_capped(monkeypatch):
    """A caller cannot pull an unbounded result set: limit is clamped to _MAX_LOG_LIMIT."""
    monkeypatch.setenv("LOKI_URL", "http://loki.local")
    app = create_app()  # real gateway client built before we patch AsyncClient
    captured: dict = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, path, params=None):
            captured.update(params or {})
            return httpx.Response(200, json={"data": {"result": []}})

    monkeypatch.setattr("app.routers.api.httpx.AsyncClient", _FakeClient)
    with TestClient(app) as c:
        c.post("/auth/login", json={"password": "admin-pw"})
        assert c.get("/api/logs", params={"limit": 999999}).status_code == 200
    assert captured["limit"] == 1000  # capped


def test_at_hash_matches_known_vector():
    import hashlib

    from app.oidc import _at_hash_matches, _b64url

    token = "user-access-token"
    expected = _b64url(hashlib.sha256(token.encode()).digest()[:16])
    assert _at_hash_matches("RS256", token, expected) is True
    assert _at_hash_matches("RS256", token, "tampered") is False
    # Wrong hash size for the alg → mismatch (RS512 would use SHA-512's left half).
    assert _at_hash_matches("RS512", token, expected) is False


# --- Silent OIDC access-token refresh (review #4) ----------------------------


def test_oidc_proxy_refreshes_on_401_and_retries(oidc_client):
    """A proxied call whose relayed token has expired triggers a silent refresh and a
    single retry with the new token — the SPA never sees the 401."""
    c, app = oidc_client
    seen = []

    async def _g(path, bearer=None):
        seen.append((path, bearer))
        # The expired user token is rejected; the refreshed token is accepted.
        if bearer == _FakeOIDC.USER_TOKEN:
            return httpx.Response(401, json={"detail": "token expired"})
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    resp = c.get("/api/devices")
    assert resp.status_code == 200
    # First attempt used the (expired) user token, the retry used the refreshed one.
    assert seen == [("/devices", _FakeOIDC.USER_TOKEN), ("/devices", _FakeOIDC.REFRESHED_TOKEN)]
    assert app.state.oidc.refreshes == 1
    assert app.state.oidc.last["refresh_used"] == _FakeOIDC.REFRESH_TOKEN


def test_oidc_refresh_persists_new_tokens_for_next_call(oidc_client):
    """After a refresh, the rotated tokens are stored, so the *next* call uses the new
    access token directly (no second 401/refresh)."""
    c, app = oidc_client
    seen = []

    async def _g(path, bearer=None):
        seen.append(bearer)
        return httpx.Response(401 if bearer == _FakeOIDC.USER_TOKEN else 200, json={"devices": []})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    c.get("/api/devices")  # 401 → refresh → retry
    seen.clear()
    assert c.get("/api/devices").status_code == 200
    # Session now carries the refreshed token; no expired-token attempt, no extra refresh.
    assert seen == [_FakeOIDC.REFRESHED_TOKEN]
    assert app.state.oidc.refreshes == 1


def test_oidc_me_refreshes_before_dropping_session(oidc_client):
    """/auth/me silently refreshes rather than ending the session on a recoverable 401."""
    c, app = oidc_client

    async def _g(path, bearer=None):
        if bearer == _FakeOIDC.USER_TOKEN:
            return httpx.Response(401, json={"detail": "expired"})
        return httpx.Response(200, json={"subject": "oidc:alice", "scopes": ["devices:read"]})

    app.state.gateway.get = _g
    _do_oidc_login(c)
    me = c.get("/auth/me").json()
    assert me["kind"] == "oidc" and me["scopes"] == ["devices:read"]


def test_password_session_401_is_not_refreshed(app_client):
    """A password session has no refresh token — its 401 passes straight through."""
    c, app = app_client

    async def _g(path, bearer=None):
        return httpx.Response(401, json={"detail": "nope"})

    app.state.gateway.get = _g
    c.post("/auth/login", json={"password": "viewer-pw"})
    assert c.get("/api/devices").status_code == 401


# --- Login throttling of the break-glass password (review #3) -----------------


def test_login_throttled_after_max_failures(app_client):
    c, _ = app_client
    for _ in range(5):  # default LOGIN_MAX_FAILURES
        assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401
    blocked = c.post("/auth/login", json={"password": "wrong"})
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1


def test_lockout_blocks_even_the_correct_password(app_client):
    c, _ = app_client
    for _ in range(5):
        c.post("/auth/login", json={"password": "wrong"})
    # The correct admin password is refused while the IP is locked out.
    assert c.post("/auth/login", json={"password": "admin-pw"}).status_code == 429


def test_successful_login_resets_failure_streak(app_client):
    c, _ = app_client
    for _ in range(4):  # under the limit of 5
        assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401
    assert c.post("/auth/login", json={"password": "admin-pw"}).json() == {"role": "admin"}
    # Streak cleared by the success — a subsequent wrong attempt is a 401, not an instant 429.
    assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401


def test_throttle_is_per_ip_via_trusted_forwarded_for(monkeypatch):
    monkeypatch.setenv("LOGIN_MAX_FAILURES", "2")
    monkeypatch.setenv("TRUST_FORWARDED_FOR", "true")
    app = create_app()
    with TestClient(app) as c:
        a = {"X-Forwarded-For": "203.0.113.1"}
        b = {"X-Forwarded-For": "203.0.113.2"}
        for _ in range(2):
            assert c.post("/auth/login", json={"password": "wrong"}, headers=a).status_code == 401
        assert c.post("/auth/login", json={"password": "wrong"}, headers=a).status_code == 429
        # A different source IP has its own budget and is unaffected.
        assert c.post("/auth/login", json={"password": "wrong"}, headers=b).status_code == 401


def test_login_throttle_window_rolls_off(monkeypatch):
    from app import throttle as thr

    clock = {"t": 1000.0}
    monkeypatch.setattr(thr.time, "monotonic", lambda: clock["t"])
    t = thr.LoginThrottle(max_failures=2, window=60)
    t.record_failure("ip")
    t.record_failure("ip")
    assert t.retry_after("ip") > 0  # locked out
    clock["t"] += 61  # the whole window elapses
    assert t.retry_after("ip") == 0  # failures aged out
    # A success clears an in-window streak immediately.
    t.record_failure("ip")
    t.record_success("ip")
    assert t.retry_after("ip") == 0
