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
    async def _r(method, path, json=None):
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
