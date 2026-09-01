# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0026: the correlation id starts at the console, not at the gateway.

The gateway accepts one service identity per device permanently and leans "who really did
this" on joining its audit record to the device's own log by request id. A human's action
starts in this console, so if the BFF minted nothing and forwarded nothing the chain would
be broken at its first link — the BFF's audit row would share no key with the gateway's,
and the browser would have nothing to quote in a support ticket.

These tests treat carrying the id as required, and look at what leaves the process rather
than at the code that assembles it: a hook installed on the client is invisible to a test
that patches the method used to call it.
"""

import os

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.correlation import (  # noqa: E402
    CORRELATION_HEADER,
    current_request_id,
    stamp_correlation,
    use_request_id,
    with_correlation_hook,
)
from app.gateway_client import GatewayClient  # noqa: E402
from app.main import create_app  # noqa: E402


class _Settings:
    gateway_url = "http://gateway.invalid"
    gateway_token = "tok"
    gateway_api_prefix = "/v1"


@pytest.fixture
def app_client():
    app = create_app()
    with TestClient(app) as c:
        yield c, app


# --- the front door ----------------------------------------------------------


def test_the_browser_is_told_the_id_its_action_will_be_logged_under(app_client):
    c, _ = app_client
    resp = c.get("/healthz")
    assert resp.headers.get(CORRELATION_HEADER)


def test_an_id_the_caller_supplies_is_kept_rather_than_replaced(app_client):
    """An operator debugging with `curl -H 'X-Request-Id: …'` should get their own id back,
    and the gateway does the same, so one chosen id can span both processes."""
    c, _ = app_client
    resp = c.get("/healthz", headers={CORRELATION_HEADER: "rid-chosen"})
    assert resp.headers[CORRELATION_HEADER] == "rid-chosen"


def test_two_requests_do_not_share_an_id(app_client):
    c, _ = app_client
    first = c.get("/healthz").headers[CORRELATION_HEADER]
    second = c.get("/healthz").headers[CORRELATION_HEADER]
    assert first != second


def test_the_id_does_not_outlive_the_request(app_client):
    c, _ = app_client
    c.get("/healthz")
    assert current_request_id() == ""


# --- the outbound hop --------------------------------------------------------


def _intercept(client: GatewayClient) -> list[httpx.Headers]:
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json={})

    client._client._transport = httpx.MockTransport(handler)
    return seen


@pytest.mark.asyncio
async def test_every_gateway_call_carries_the_id():
    gw = GatewayClient(_Settings())
    seen = _intercept(gw)

    with use_request_id("rid-abc"):
        await gw.get("/devices")

    assert seen[0][CORRELATION_HEADER] == "rid-abc"
    await gw._client.aclose()


@pytest.mark.asyncio
async def test_a_relayed_call_carries_it_too():
    """The relay reaches another tenant's gateway through a pooled GatewayClient, so the
    property has to hold on the client, not on one router's call site."""
    gw = GatewayClient(_Settings())
    seen = _intercept(gw)

    with use_request_id("rid-relay"):
        await gw.request("POST", "/devices", json={}, bearer="user-token")

    assert seen[0][CORRELATION_HEADER] == "rid-relay"
    await gw._client.aclose()


@pytest.mark.asyncio
async def test_nothing_is_invented_when_no_request_is_in_scope():
    gw = GatewayClient(_Settings())
    seen = _intercept(gw)

    await gw.get("/devices")

    assert CORRELATION_HEADER not in seen[0]
    await gw._client.aclose()


@pytest.mark.asyncio
async def test_the_hook_overwrites_a_caller_supplied_header():
    request = httpx.Request("GET", "http://g.invalid/x", headers={CORRELATION_HEADER: "forged"})
    with use_request_id("rid-real"):
        await stamp_correlation(request)
    assert request.headers[CORRELATION_HEADER] == "rid-real"


def test_installing_the_hook_keeps_a_callers_own_hooks():
    async def other(_request):  # pragma: no cover - identity is all that is asserted
        return None

    hooks = with_correlation_hook({"request": [other]})
    assert hooks["request"] == [other, stamp_correlation]


# --- and the same id on this side's audit row --------------------------------


def test_the_audit_row_carries_the_same_id_the_browser_was_given(tmp_path, monkeypatch):
    """Not merely "an id" — the *same* id, so a person holding the value from a response
    can find the row. Reading only the inbound header left `rid` null on almost every real
    request, because browsers do not send one, so the BFF's audit row shared no key with
    the gateway's or the device's."""
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "admin-pw")
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", "acme")
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()

    with TestClient(app) as c:
        resp = c.post("/auth/login", json={"password": "nope"})  # a denial is audited
    rid = resp.headers[CORRELATION_HEADER]

    rows = app.state.audit.read(tenant="acme")
    denials = [r["content"] for r in rows if r["content"]["action"] == "auth.login"]
    assert denials, "expected an audit record for the failed login"
    assert denials[-1]["rid"] == rid
