# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The routes that make an elevated grant reachable (ADR-0013 §5a/§8/§11).

Until these existed the whole mechanism authorized nothing: the elevation was minted, held,
relayed, consumed and expired correctly, and the BFF had no route that needed it. Adding
the routes is most of the work; the rest is making sure the credential goes to *these* and
nowhere else.

Three hazards, and none of them fails loudly:

1. **The elevated credential on routine traffic.** The gateway consumes a single-use grant
   on first validation of the token, whatever route it was for. So a token handed to a
   background `GET /api/devices` burns the grant on a device list and the operation the
   operator actually elevated for is refused. Handing the step-up token to every relayed
   request looks harmless — it is a strict superset — which is exactly why this needs a
   test rather than a reading.
2. **The dependency on a route that should not have it.** The inverse of (1) and the same
   damage, introduced deliberately by copy-paste instead of by omission. Guarded by a
   closed list below rather than a per-route check, because a per-route check passes for
   every route nobody thought to write one for.
3. **Break-glass reaching the credential routes.** A password session proxies with the
   stack's *admin* gateway token, which carries every `backup:*` scope. On those routes the
   BFF's own gate is not one control among several — it is the only one.
"""

from __future__ import annotations

import inspect
import json
import os
import time

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.grants import (  # noqa: E402
    authorize_act_on_tenant,
    elevated_spec,
    record_elevated_grant,
)
from app.main import create_app  # noqa: E402
from app.routers import api as api_routes  # noqa: E402
from app.security import (  # noqa: E402
    PLANE_PROVIDER,
    SCOPE_PROVIDER_ADMIN,
    SCOPE_PROVIDER_CREDENTIALS,
    SCOPE_PROVIDER_INVOKE,
)

TENANT = "acme"
WHY = "ticket INC-9001: reproducing the fault needs one live tool call"
STEP_UP_ACR = "urn:mcp:provider:step-up"
ORDINARY_TOKEN = "ORDINARY-OPERATOR-TOKEN"
STEP_UP_TOKEN = "STEP-UP-TOKEN-CARRYING-THE-GRANT"


# --- hazard 2: the closed list -------------------------------------------------
#
# Reads the class out of the dependency's closure rather than asserting that *a* dependency
# is attached, which passes just as happily when the wrong one is. Same technique, and the
# same reason, as the gateway's `test_streamable_http.py::_route_scopes`.


def _elevated_routes() -> dict[tuple[str, str], str]:
    found: dict[tuple[str, str], str] = {}
    for route in api_routes.router.routes:
        for dep in getattr(route, "dependencies", []):
            fn = getattr(dep, "dependency", None)
            if fn is None:
                continue
            scope = inspect.getclosurevars(fn).nonlocals.get("provider_scope")
            if scope is None:
                continue
            for method in sorted(set(route.methods) - {"HEAD", "OPTIONS"}):
                found[(method, route.path)] = scope
    return found


def _password_denied_routes() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for route in api_routes.router.routes:
        for dep in getattr(route, "dependencies", []):
            if getattr(getattr(dep, "dependency", None), "__name__", "") != "deny_password_session":
                continue
            for method in sorted(set(route.methods) - {"HEAD", "OPTIONS"}):
                found.add((method, route.path))
    return found


ELEVATED = {
    ("POST", "/api/devices/{hostname}/tools/{tool}/invoke"): SCOPE_PROVIDER_INVOKE,
    ("GET", "/api/admin/backup"): SCOPE_PROVIDER_CREDENTIALS,
    ("POST", "/api/admin/backup"): SCOPE_PROVIDER_CREDENTIALS,
    ("POST", "/api/admin/restore"): SCOPE_PROVIDER_CREDENTIALS,
}


def test_exactly_these_routes_ask_for_an_elevated_credential():
    """A closed list, asserted as equality.

    Both directions matter and only one is obvious. A missing entry means an elevated route
    relays the ordinary token and is refused upstream — annoying, visible, safe. An **extra**
    entry means a routine route starts spending single-use grants on ordinary traffic, which
    is silent, and is the defect this whole file exists because of.
    """
    assert _elevated_routes() == ELEVATED


#: The download leg of the two-step export. Break-glass is refused here — it serves the very
#: archive a credentials export produced — but it deliberately does **not** demand an
#: elevation of its own: `provider:credentials` is single-use and was spent preparing the
#: file, so requiring it again would make the download unreachable by the operator who just
#: authorized it. Its authorization is the pending record in the session instead.
#:
#: Named explicitly rather than folded into a looser rule, so that adding a second
#: break-glass-denied route without an elevation has to be a decision someone writes down.
CREDENTIAL_BEARING_WITHOUT_ELEVATION = {("GET", "/api/admin/backup/download")}


def test_the_credential_routes_are_the_ones_closed_to_break_glass():
    """Every route that can yield credential material refuses a password session, and no
    other route does.

    That set is the `provider:credentials` routes *plus* the download leg they produce a file
    for. Derived from the table rather than restated, so the two cannot drift."""
    expected = {rt for rt, scope in ELEVATED.items() if scope == SCOPE_PROVIDER_CREDENTIALS}
    expected |= CREDENTIAL_BEARING_WITHOUT_ELEVATION
    assert _password_denied_routes() == expected


def test_the_download_leg_does_not_demand_a_second_elevation():
    """The reason it is on the exception list, asserted rather than trusted.

    A single-use grant is spent by the export. If this route also declared
    `require_elevated`, every prepared archive would be undownloadable — and the failure
    would arrive at the worst moment, after the operator had already spent their step-up.
    """
    assert ("GET", "/api/admin/backup/download") not in _elevated_routes()


# --- rig -----------------------------------------------------------------------


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", "https://provider-idp.example.com")
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("PROVIDER_STEP_UP_ACR", STEP_UP_ACR)
    monkeypatch.setenv("PROVIDER_STEP_UP_REDIRECT_URL", "https://console.example.com/auth/provider/step-up/callback")
    monkeypatch.setenv("PROVIDER_STEP_UP_SCOPE_TEMPLATE", "mcp:tenant:{tenant} mcp:grant:{grant_class}")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", TENANT)
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)


@pytest.fixture
def console(monkeypatch, tmp_path):
    _env(monkeypatch, tmp_path)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _seed(client, app, data: dict) -> None:
    assert client.post("/auth/login", json={"password": "admin-pw"}).status_code == 200
    live = app.state.sessions._data
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, dict(data))


def _elevated_session(provider_scope: str = SCOPE_PROVIDER_INVOKE) -> dict:
    """A provider session holding a live act **and** a live elevation of one class.

    Built through `record_elevated_grant` rather than by writing the session key directly:
    that function is where the claim is checked against the class, so a hand-written record
    would be a shape this code has never actually produced.
    """
    now = time.time()
    sess = {
        "kind": "oidc",
        "plane": PLANE_PROVIDER,
        "sub": "u-provider-1",
        "provider_scopes": [SCOPE_PROVIDER_ADMIN],
        "access_token": ORDINARY_TOKEN,
    }
    authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=now)
    record_elevated_grant(
        sess,
        tenant=TENANT,
        provider_scope=provider_scope,
        justification=WHY,
        claim={
            "id": f"g-{provider_scope}",
            "tenant": TENANT,
            "scopes": list(elevated_spec(provider_scope).gateway_scopes),
        },
        access_token=STEP_UP_TOKEN,
        auth_time=now - 5,
        now=now,
    )
    return sess


class _Upstream:
    """Records the bearer and headers of every relayed call, and answers plausibly.

    The MCP handshake is answered as the gateway answers it — a session id in a response
    *header* — because that is the one part of this route the BFF cannot invent.
    """

    def __init__(self, *, status=200, handshake_status=200, session_id="sess-1", payload=None):
        # The handshake's outcome is separate from the call's on purpose. Collapsing them
        # into one status made "the tool failed" indistinguishable from "the handshake
        # failed", and the two take different paths through the route — the second returns
        # before there is anything to tear down.
        self.status = status
        self.handshake_status = handshake_status
        self.session_id = session_id
        self.payload = payload if payload is not None else {"ok": True}
        self.calls: list[dict] = []

    async def get(self, path, bearer=None, headers=None):
        self.calls.append({"method": "GET", "path": path, "bearer": bearer, "headers": headers or {}})
        return httpx.Response(self.status, json=self.payload)

    async def request(self, method, path, json=None, bearer=None, headers=None):
        self.calls.append({"method": method, "path": path, "json": json, "bearer": bearer, "headers": headers or {}})
        body = json or {}
        if body.get("method") == "initialize":
            if self.handshake_status >= 400:
                return httpx.Response(self.handshake_status, json=self.payload)
            hdrs = {"Mcp-Session-Id": self.session_id} if self.session_id else {}
            return httpx.Response(self.handshake_status, json={"jsonrpc": "2.0", "id": 1, "result": {}}, headers=hdrs)
        return httpx.Response(self.status, json=self.payload)

    def bearers(self) -> list:
        return [c["bearer"] for c in self.calls]


def _attach(app, upstream: _Upstream) -> _Upstream:
    app.state.gateway.get = upstream.get
    app.state.gateway.request = upstream.request
    return upstream


# --- hazard 1: the credential goes only where it was asked for -----------------


def test_a_routine_read_does_not_receive_the_elevated_credential(console):
    """The defect this fix exists for. A provider session holding a live elevation makes an
    ordinary read; the step-up token must not go with it. It would be accepted — the grant
    is a superset — and the gateway would consume it, leaving the operation the operator
    elevated for to fail with a grant that was spent on a device list."""
    client, app = console
    up = _attach(app, _Upstream(payload={"devices": []}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    assert client.get("/api/devices").status_code == 200
    assert up.bearers() == [ORDINARY_TOKEN]


def test_a_routine_read_does_not_spend_a_single_use_elevation(console):
    """The same property observed from the session rather than the wire, because the two
    could disagree: a bearer choice that got it right while still calling `spend` would
    leave the operator's own next request refused for a grant nothing used."""
    client, app = console
    _attach(app, _Upstream(payload={"devices": []}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    client.get("/api/devices")
    stored = next(iter(app.state.sessions._data.values()))[1]
    assert stored.get("elevated_grant") is not None


def test_the_elevated_route_receives_the_step_up_credential(console):
    """The converse, so the fix above cannot be 'never hand it over at all' — which would
    pass every test in the section above and break the entire feature."""
    client, app = console
    up = _attach(app, _Upstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    assert client.get("/api/admin/backup").status_code == 200
    assert up.bearers() == [STEP_UP_TOKEN]


def test_an_invoke_elevation_cannot_pay_for_a_credentials_route(console):
    """The two classes differ in lifetime and in single-use, so being handed the wrong one
    is not a narrower grant — it is a different one. Refused here rather than relayed and
    left to the gateway, so the BFF can still explain itself in an audit record."""
    client, app = console
    up = _attach(app, _Upstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_INVOKE))

    resp = client.get("/api/admin/backup")
    assert resp.status_code == 403
    assert "provider:credentials" in resp.json()["detail"]
    assert up.calls == []  # nothing relayed, so nothing spent


def test_an_elevated_route_without_any_elevation_says_what_to_do(console):
    client, app = console
    up = _attach(app, _Upstream())
    now = time.time()
    sess = {
        "kind": "oidc",
        "plane": PLANE_PROVIDER,
        "sub": "u-provider-1",
        "provider_scopes": [SCOPE_PROVIDER_ADMIN],
        "access_token": ORDINARY_TOKEN,
    }
    authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=now)
    _seed(client, app, sess)

    resp = client.get("/api/admin/backup")
    assert resp.status_code == 403 and "elevation" in resp.json()["detail"]
    assert up.calls == []


# --- hazard 3: break-glass ------------------------------------------------------


def test_a_password_admin_cannot_export_a_backup(console):
    """It would proxy with the stack's admin token, which holds every `backup:*` scope: a
    complete credential dump with no step-up and no grant in either audit chain."""
    client, app = console
    up = _attach(app, _Upstream())
    assert client.post("/auth/login", json={"password": "admin-pw"}).status_code == 200

    for method, path in (("GET", "/api/admin/backup"), ("POST", "/api/admin/backup"), ("POST", "/api/admin/restore")):
        resp = client.request(method, path, json={})
        assert resp.status_code == 403, (method, path)
    assert up.calls == []


def test_a_password_admin_may_still_invoke_a_tool(console):
    """Break-glass keeps tool invocation: the admin token already carries `tools:call`, and
    repairing a broken fleet is what that login is for. Stated as a test so the blanket
    'refuse password sessions on elevated routes' simplification cannot creep in."""
    client, app = console
    _attach(app, _Upstream(payload={"jsonrpc": "2.0", "id": 2, "result": {"content": []}}))
    assert client.post("/auth/login", json={"password": "admin-pw"}).status_code == 200

    resp = client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {}})
    assert resp.status_code == 200


def test_a_password_viewer_cannot_invoke_a_tool(console):
    client, app = console
    up = _attach(app, _Upstream())
    assert client.post("/auth/login", json={"password": "viewer-pw"}).status_code == 200

    assert client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {}}).status_code == 403
    assert up.calls == []


# --- the invocation sequence ----------------------------------------------------


def test_invoking_a_tool_runs_the_handshake_and_tears_it_down(console):
    """`tools/call` cannot be sent on its own: the gateway refuses a sessionless message
    carrying an id with `400 — send an initialize request first`. So the route runs the
    whole exchange, and the session id it was given has to travel on the calls that follow."""
    client, app = console
    up = _attach(app, _Upstream(payload={"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text"}]}}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_INVOKE))

    resp = client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {"host": "x"}})
    assert resp.status_code == 200
    assert resp.json()["result"]["content"] == [{"type": "text"}]

    methods = [(c["method"], (c.get("json") or {}).get("method")) for c in up.calls]
    assert methods == [("POST", "initialize"), ("POST", "tools/call"), ("DELETE", None)]
    assert up.calls[1]["headers"]["Mcp-Session-Id"] == "sess-1"
    assert up.calls[2]["headers"]["Mcp-Session-Id"] == "sess-1"
    assert up.calls[1]["json"]["params"] == {"name": "probe", "arguments": {"host": "x"}}
    # Every call in the sequence is one principal's: an MCP session is bound to its owner
    # upstream, so a mid-sequence change of bearer would 403 rather than merely look untidy.
    assert set(up.bearers()) == {STEP_UP_TOKEN}


def test_the_session_is_torn_down_even_when_the_call_fails(console):
    """Otherwise a failing tool leaks a gateway session per attempt — and a failing tool is
    exactly the one an operator retries."""
    client, app = console
    up = _attach(app, _Upstream(status=500, payload={"detail": "device exploded"}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_INVOKE))

    client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {}})
    assert [c["method"] for c in up.calls][-1] == "DELETE"


def test_a_refused_handshake_is_passed_through_not_rewritten(console):
    """The handshake's own refusal carries the reason — an unapproved fingerprint, an
    inactive pod, a refused grant. Replacing it with 'could not invoke the tool' costs the
    operator the one sentence that says what to do."""
    client, app = console
    _attach(app, _Upstream(handshake_status=409, payload={"detail": "dev1: fingerprint change awaiting approval"}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_INVOKE))

    resp = client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {}})
    assert resp.status_code == 409
    assert "awaiting approval" in resp.json()["detail"]


def test_a_handshake_with_no_session_id_is_not_pressed_on_with(console):
    """Continuing without one would send `tools/call` sessionless, and the gateway's refusal
    would name a missing header rather than the gateway's own broken handshake."""
    client, app = console
    _attach(app, _Upstream(session_id=""))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_INVOKE))

    resp = client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {}})
    assert resp.status_code == 502


def test_non_object_arguments_are_refused_before_any_upstream_call(console):
    client, app = console
    up = _attach(app, _Upstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_INVOKE))

    resp = client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": ["not", "an", "object"]})
    assert resp.status_code == 400
    assert up.calls == []


# --- restore: the destructive direction is never reached by omission -------------


def test_a_restore_with_no_dry_run_field_arrives_at_the_gateway_as_a_dry_run(console):
    """The gateway defaults `dry_run` to true itself, and this asserts the *BFF* does not
    undo that — that nothing in the request-building forces the field implicitly. A thin
    wrapper behaving subtly differently from the system it wraps is a gap this project has
    shipped twice before, and the failure here is silent and destructive."""
    client, app = console
    up = _attach(app, _Upstream(payload={"would_restore": 3}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    resp = client.post("/api/admin/restore", json={"archive": {"envelope": {}}})
    assert resp.status_code == 200
    assert up.calls[0]["json"]["dry_run"] is True


def test_a_restore_may_still_be_asked_for_explicitly(console):
    """The converse, so 'always force a dry run' cannot pass the test above while making
    restore impossible."""
    client, app = console
    up = _attach(app, _Upstream(payload={"restored": 3}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    client.post("/api/admin/restore", json={"archive": {"envelope": {}}, "dry_run": False})
    assert up.calls[0]["json"]["dry_run"] is False


def test_an_empty_restore_body_is_still_a_dry_run(console):
    """A body the BFF could not parse must not become a body with no `dry_run` in it."""
    client, app = console
    up = _attach(app, _Upstream(payload={"detail": "archive required"}, status=400))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    client.post("/api/admin/restore", content=b"not json", headers={"Content-Type": "application/json"})
    assert up.calls[0]["json"]["dry_run"] is True


# --- the audit chain records the act, never its contents -------------------------


def test_an_export_is_audited_without_its_archive_or_passphrase(console):
    """The BFF's chain records that an export happened and by whom. It must never carry the
    archive or a passphrase into the record — the one thing this whole design protects."""
    client, app = console
    _attach(app, _Upstream(payload={"envelope": {"kind": "portable"}, "devices": ["secret-credential"]}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    client.post("/api/admin/backup", json={"kind": "portable", "passphrase": "correct-horse-battery"})

    rows = app.state.audit.read(tenant=TENANT, limit=50)
    exports = [r["content"] for r in rows if r["content"] and r["content"]["action"] == "backup.export_portable"]
    assert len(exports) == 1
    blob = repr(exports[0])
    assert "correct-horse-battery" not in blob and "secret-credential" not in blob


def test_an_elevated_call_refused_upstream_is_not_retried_without_the_elevation(console):
    """A 401 on an elevated route must surface, not trigger the ordinary refresh-and-retry.

    A refresh produces an *ordinary* access token — no `mcp_grant` claim — so the retry
    cannot do what the first attempt was for, and by then the elevation has already been
    spent handing over the first token. The retry would trade a truthful "your elevation was
    refused" for a confusing 403 on a route the operator had just been told they could use.
    """
    client, app = console
    up = _attach(app, _Upstream(status=401, payload={"detail": "elevated grant refused"}))
    sess = _elevated_session(SCOPE_PROVIDER_CREDENTIALS)
    sess["refresh_token"] = "a-usable-refresh-token"
    _seed(client, app, sess)

    refreshed = []

    class _Idp:
        async def refresh_tokens(self, *, refresh_token):
            refreshed.append(refresh_token)
            return {"access_token": "A-FRESH-ORDINARY-TOKEN"}

    app.state.oidc = _Idp()

    resp = client.get("/api/admin/backup")
    assert resp.status_code == 401
    assert refreshed == [], "an elevated request was retried with a token that cannot carry the grant"
    assert up.bearers() == [STEP_UP_TOKEN]


def test_a_routine_call_refused_upstream_is_still_retried(console):
    """The control. Without it, "never retry" would pass the test above and silently undo
    the silent-refresh behaviour every ordinary screen depends on."""
    client, app = console
    _attach(app, _Upstream(status=401, payload={"detail": "expired"}))
    sess = _elevated_session(SCOPE_PROVIDER_INVOKE)
    sess["refresh_token"] = "a-usable-refresh-token"
    _seed(client, app, sess)

    refreshed = []

    class _Idp:
        async def refresh_tokens(self, *, refresh_token):
            refreshed.append(refresh_token)
            return {"access_token": "A-FRESH-ORDINARY-TOKEN"}

    app.state.oidc = _Idp()

    client.get("/api/devices")
    assert refreshed == ["a-usable-refresh-token"]


# --- the transport header channel cannot be used to change identity --------------


@pytest.mark.parametrize("spelling", ["Authorization", "authorization", "AUTHORIZATION"])
@pytest.mark.asyncio
async def test_relayed_transport_headers_cannot_displace_the_bearer(spelling):
    """`GatewayClient.request` grew a `headers` parameter for the MCP session id. It must not
    become a second way to choose a credential: the bearer is decided in one place
    (`upstream_bearer`, ADR-0013 §4/§5a), and a route that could pass its own
    `Authorization` would be a way around that decision rather than an addition to it."""
    from types import SimpleNamespace

    from app.gateway_client import GatewayClient

    seen = {}

    class _Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            # Every value, not `.get` — two spellings of one header do not overwrite each
            # other in a dict, they arrive as two headers, and reading only the first would
            # hide exactly the smuggling this asserts against.
            seen["auth"] = request.headers.get_list("authorization")
            return httpx.Response(200, json={})

    gw = GatewayClient(
        SimpleNamespace(gateway_url="http://gw.invalid", gateway_token="ADMIN-KEY", gateway_api_prefix="/v1")
    )
    gw._client = httpx.AsyncClient(base_url="http://gw.invalid", transport=_Transport())
    try:
        await gw.request(
            "POST", "/devices/d/mcp", json={}, bearer="THE-CHOSEN-TOKEN", headers={spelling: "Bearer SMUGGLED"}
        )
    finally:
        await gw.aclose()
    assert seen["auth"] == ["Bearer THE-CHOSEN-TOKEN"]


# --- the two-step export (ADR-0011 §8) -----------------------------------------
#
# One request cannot give an operator both the file and the passphrase that opens it: the
# archive has to arrive as a native browser download, and a download cannot read the header
# the gateway delivers the passphrase in. So: prepare, then claim.


class _ExportUpstream(_Upstream):
    """A gateway that mints a passphrase, as ADR-0011 has it."""

    MINTED = "minted-passphrase-value-abc123"

    async def request(self, method, path, json=None, bearer=None, headers=None):
        self.calls.append({"method": method, "path": path, "json": json, "bearer": bearer})
        return httpx.Response(
            200, json={"kind": "portable", "devices": []}, headers={"X-Backup-Passphrase": self.MINTED}
        )


def _prepare(client) -> dict:
    resp = client.post("/api/admin/backup", json={"kind": "portable"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_preparing_an_export_reveals_the_passphrase_and_withholds_the_archive(console):
    """The first leg returns no archive at all — only the secret, once, and a token."""
    client, app = console
    _attach(app, _ExportUpstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    body = _prepare(client)
    assert body["passphrase"] == _ExportUpstream.MINTED
    assert body["download_token"]
    assert "devices" not in body and "archive" not in body


def test_the_download_serves_a_file_not_a_json_body(console):
    """§8: a native browser download, not a decoded blob. Content-Disposition is what makes
    the browser save it rather than render it."""
    client, app = console
    _attach(app, _ExportUpstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    token = _prepare(client)["download_token"]
    resp = client.get(f"/api/admin/backup/download?token={token}")
    assert resp.status_code == 200
    assert resp.headers["content-disposition"].startswith("attachment; filename=")
    assert "devices" in resp.json()


def test_the_archive_is_served_once(console):
    """Claimed before it is served, so a replayed request finds nothing even if the first
    response never reached the browser. Losing a download to a flaky network is recoverable
    by exporting again; serving a credential dump twice is not."""
    client, app = console
    _attach(app, _ExportUpstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    token = _prepare(client)["download_token"]
    assert client.get(f"/api/admin/backup/download?token={token}").status_code == 200
    assert client.get(f"/api/admin/backup/download?token={token}").status_code == 404


def test_the_passphrase_is_never_stored_beside_the_archive(console):
    """The pending record is a blob this process cannot open — a portable archive is sealed
    under the minted passphrase, which goes to the browser and nowhere else. That is what
    makes parking it in the session for two minutes acceptable rather than a credential cache.
    """
    client, app = console
    _attach(app, _ExportUpstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    _prepare(client)
    stored = json.dumps(next(iter(app.state.sessions._data.values()))[1], default=str)
    assert _ExportUpstream.MINTED not in stored


def test_a_download_token_is_worthless_to_another_session(console):
    """The token travels in a URL, which is logged by every proxy on the way. It is only ever
    an index into *this* session's pending record, so a leaked one opens nothing."""
    client, app = console
    _attach(app, _ExportUpstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))
    token = _prepare(client)["download_token"]

    # A different session — same deployment, same everything else.
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))
    assert client.get(f"/api/admin/backup/download?token={token}").status_code == 404


def test_an_expired_preparation_is_refused_and_says_so(console):
    """410 rather than 404: the archive existed and the operator did nothing wrong, so the
    console can tell them to export again instead of implying they mistyped something."""
    client, app = console
    _attach(app, _ExportUpstream())
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))
    token = _prepare(client)["download_token"]

    sid, (expires, data) = next(iter(app.state.sessions._data.items()))
    data["pending_backup"]["expires_at"] = time.time() - 1
    app.state.sessions._data[sid] = (expires, data)

    assert client.get(f"/api/admin/backup/download?token={token}").status_code == 410


def test_a_failed_export_stages_nothing(console):
    """A refusal upstream must not leave a claimable token behind."""
    client, app = console
    _attach(app, _Upstream(status=409, payload={"detail": "no key"}))
    _seed(client, app, _elevated_session(SCOPE_PROVIDER_CREDENTIALS))

    assert client.post("/api/admin/backup", json={"kind": "portable"}).status_code == 409
    stored = next(iter(app.state.sessions._data.values()))[1]
    assert "pending_backup" not in stored
