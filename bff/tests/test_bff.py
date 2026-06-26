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

from app.main import create_app  # noqa: E402


@pytest.fixture
def app_client():
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _fake_get(payload, status=200):
    async def _g(path):
        return httpx.Response(status, json=payload)

    return _g


def _fake_request(payload, status=200):
    async def _r(method, path, json=None):
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
    assert c.get("/auth/me").json() == {"role": "admin"}


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


def _capture_get(seen, payload, status=200):
    async def _g(path):
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


def test_device_reads_require_session(app_client):
    c, _ = app_client
    assert c.get("/api/devices/dev/diagnostics").status_code == 401
    assert c.get("/api/devices/dev/tools").status_code == 401


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
