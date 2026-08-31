# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0017 §7b — a provider **monitor** may raise a support request, for read scopes only.

Found in the lab, not here: the console offered `provview` (`provider:monitor`) the whole
raise form and the BFF answered 403 on submit, because every support-request route was
gated on `provider:admin`. Two changes follow from that, and this file holds the second.

The first is the gate: asking is not itself an authority — the tenant decides — so raising
is now monitor-or-admin, along with poll/hold/release, which have to move with it or the
role can ask and never learn the answer.

The second is the constraint, and it is the one that needs testing rather than asserting:
**what a monitor may ask for is narrowed here, in the BFF, and nowhere else.** The tenant's
gateway sees the provider's single `support:request` credential (§7a), not which provider
operator is behind it, so it cannot tell a monitor's raise from an admin's. The browser is
not a gate. If this check is wrong, a narrowed checkbox list is decoration and a hand-made
POST carries whatever it likes — which is why every refusal test below asserts the gateway
was **never called**, not merely that the response was a 403.
"""

from __future__ import annotations

import os

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import json  # noqa: E402
import pathlib  # noqa: E402
import re  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402
from app.security import MONITOR_REQUESTABLE_SCOPES, requestable_scopes_for  # noqa: E402

PROVIDER_ISS = "https://provider-idp.example.com"
TENANT_ID = "t-1"


class _Gateway:
    """Records every call the BFF makes, so a refusal can be shown to have relayed nothing."""

    def __init__(self):
        self.calls: list[dict] = []
        self.responses: dict[tuple[str, str], httpx.Response] = {}

    def when(self, method: str, path: str, response: httpx.Response) -> None:
        self.responses[(method, path)] = response

    async def request(self, method, path, *, json=None, bearer=None, headers=None):
        self.calls.append({"method": method, "path": path, "json": json, "bearer": bearer})
        return self.responses.get((method, path), httpx.Response(200, json={}))

    async def get(self, path, *, bearer=None):
        return await self.request("GET", path, bearer=bearer)


@pytest.fixture
def provider_console(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    # Both groups mapped, which is the lab's own shape: mcp-operators -> monitor,
    # mcp-admins -> admin.
    monkeypatch.setenv(
        "PROVIDER_GROUP_SCOPES",
        '{"mcp-admins": "provider:admin", "mcp-operators": "provider:monitor"}',
    )
    monkeypatch.setenv(
        "PROVIDER_TENANT_REGISTRY",
        f'[{{"tenant_id": "{TENANT_ID}", "display_name": "Tenant One", "gateway_url": "http://t1:8000"}}]',
    )
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()
    gw = _Gateway()

    async def _fake_pool_get(tenant_id):
        if tenant_id != TENANT_ID:
            raise KeyError(tenant_id)
        return gw

    app.state.gateway_pool.get = _fake_pool_get
    with TestClient(app) as c:
        yield c, app, gw


def _seed(client, app, *, sub: str = "op-14", scopes=("provider:monitor",)) -> None:
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    live = app.state.sessions._data
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, {"kind": "oidc", "plane": "provider", "sub": sub, "provider_scopes": list(scopes)})


def _audited(app, action: str) -> list[dict]:
    rows = app.state.audit.read(tenant="default", limit=200)
    return [r["content"] for r in reversed(rows) if r["content"] and r["content"]["action"] == action]


def _raise(client, scopes):
    return client.post(
        "/provider/support-requests",
        json={"tenant_id": TENANT_ID, "requested_scopes": list(scopes), "justification": "INC-9"},
    )


# --- the gate: a monitor may now ask -----------------------------------------------------


def test_monitor_may_raise_for_read_scopes(provider_console):
    client, app, gw = provider_console
    _seed(client, app)
    gw.when("POST", "/support-requests", httpx.Response(201, json={"request_id": "r-1", "status": "pending"}))

    resp = _raise(client, ["devices:read", "metrics:read"])

    # 200, not the gateway's 201: this route returns a dict, so FastAPI supplies the status.
    # Pre-existing relay behaviour, asserted here only so the test does not read as a claim
    # that upstream codes propagate.
    assert resp.status_code == 200
    assert resp.json()["request_id"] == "r-1"
    # Relayed with the BFF's own service credential and the session's own subject — the
    # §7 properties are unchanged by widening who may ask.
    assert gw.calls[0]["bearer"] is None
    assert gw.calls[0]["json"]["provider_subject"] == "op-14"
    assert gw.calls[0]["json"]["requested_scopes"] == ["devices:read", "metrics:read"]


def test_monitor_may_poll_its_own_request(provider_console):
    """Raising without polling is a role that can ask and never learn the answer."""
    client, app, gw = provider_console
    _seed(client, app)
    gw.when("GET", "/support-requests/r-1?provider_subject=op-14", httpx.Response(200, json={"status": "pending"}))

    resp = client.get(f"/provider/support-requests/r-1?tenant_id={TENANT_ID}")

    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"


def test_monitor_may_read_and_release_its_own_grant(provider_console):
    """And releasing: a role that cannot hand back what it holds is worse than one that
    never held it."""
    client, app, gw = provider_console
    _seed(client, app)
    gw.when(
        "GET",
        "/support-requests/r-1?provider_subject=op-14",
        httpx.Response(200, json={"status": "approved", "grant_id": "g-1", "credential": "tok"}),
    )
    assert client.get(f"/provider/support-requests/r-1?tenant_id={TENANT_ID}").status_code == 200

    held = client.get("/provider/support-grant")
    assert held.status_code == 200
    assert held.json() == {"held": True, "grant_id": "g-1", "tenant_id": TENANT_ID}

    released = client.delete("/provider/support-grant")
    assert released.status_code == 200
    assert released.json() == {"released": "g-1"}
    assert {"method": "DELETE", "path": "/support-grants/g-1"} in [
        {"method": c["method"], "path": c["path"]} for c in gw.calls
    ]


# --- the constraint: and only for read scopes --------------------------------------------


@pytest.mark.parametrize("scope", ["devices:write", "tools:call", "backup:read", "backup:restore"])
def test_monitor_refused_any_scope_above_its_role(provider_console, scope):
    client, app, gw = provider_console
    _seed(client, app)

    resp = _raise(client, [scope])

    assert resp.status_code == 403
    assert scope in resp.json()["detail"]
    # The property, not the status code: nothing reached the tenant's gateway. A refusal
    # that still relayed would mean the tenant saw a request its own side must now judge.
    assert gw.calls == []


def test_a_mixed_request_is_refused_whole_and_not_silently_narrowed(provider_console):
    """Dropping the disallowed scope and raising the rest would be the dangerous kindness:
    the operator believes they asked for `tools:call`, the tenant admin approves what they
    see, and the two disagree about what was authorised."""
    client, app, gw = provider_console
    _seed(client, app)

    resp = _raise(client, ["devices:read", "tools:call"])

    assert resp.status_code == 403
    assert gw.calls == []


def test_the_refusal_names_the_role_and_the_scopes_refused(provider_console):
    client, app, gw = provider_console
    _seed(client, app)

    detail = _raise(client, ["devices:write", "tools:call"]).json()["detail"]

    # What it may ask for, and which of the named scopes were the problem — an operator
    # who cannot see why they were refused raises a ticket instead of fixing the request.
    assert "devices:read" in detail and "metrics:read" in detail
    assert "devices:write" in detail and "tools:call" in detail


def test_the_refusal_is_audited_as_denied(provider_console):
    client, app, gw = provider_console
    _seed(client, app)

    _raise(client, ["devices:write"])

    records = _audited(app, "provider.support_request.raise")
    assert len(records) == 1
    assert records[0]["outcome"] == "denied"
    assert records[0]["detail"]["reason"] == "scope_above_role"
    assert records[0]["detail"]["requested_scopes"] == ["devices:write"]


def test_the_scope_check_runs_before_the_tenant_is_resolved(provider_console):
    """An unknown tenant *and* a scope above the role reads as the authority failure. The
    order matters for the message the operator gets, and for not answering a question about
    which tenants exist on a request that was never allowed."""
    client, app, gw = provider_console
    _seed(client, app)

    resp = client.post(
        "/provider/support-requests",
        json={"tenant_id": "t-does-not-exist", "requested_scopes": ["devices:write"], "justification": ""},
    )

    assert resp.status_code == 403


# --- admin is deliberately unconstrained --------------------------------------------------


def test_admin_may_still_request_beyond_the_consoles_own_menu(provider_console):
    """The pre-existing behaviour, asserted so §7b cannot quietly narrow it: what an admin
    may ask for is bounded by the tenant's RBAC and a tenant admin's judgement, not by a
    list in this process."""
    client, app, gw = provider_console
    _seed(client, app, scopes=("provider:admin",))
    gw.when("POST", "/support-requests", httpx.Response(201, json={"request_id": "r-2", "status": "pending"}))

    resp = _raise(client, ["devices:write", "tools:call", "backup:restore"])

    assert resp.status_code == 200
    assert gw.calls[0]["json"]["requested_scopes"] == ["devices:write", "tools:call", "backup:restore"]


def test_holding_both_scopes_is_treated_as_admin(provider_console):
    """An estate running one directory across both groups will produce this session. The
    higher authority wins — the alternative, intersecting them, would make adding a group
    *remove* capability."""
    client, app, gw = provider_console
    _seed(client, app, scopes=("provider:monitor", "provider:admin"))
    gw.when("POST", "/support-requests", httpx.Response(201, json={"request_id": "r-3"}))

    assert _raise(client, ["devices:write"]).status_code == 200


def test_a_session_with_no_provider_scope_still_cannot_raise(provider_console):
    """§7b widens the gate to monitor, not to any authenticated provider session. An
    unmapped group grants nothing (`provider_scopes_for_groups`), and that must survive."""
    client, app, gw = provider_console
    _seed(client, app, scopes=())

    assert _raise(client, ["devices:read"]).status_code == 403
    assert gw.calls == []


# --- the policy function itself -----------------------------------------------------------


def test_requestable_scopes_for_returns_none_only_for_admin():
    assert requestable_scopes_for(["provider:admin"]) is None
    assert requestable_scopes_for(["provider:monitor"]) == MONITOR_REQUESTABLE_SCOPES
    assert requestable_scopes_for([]) == MONITOR_REQUESTABLE_SCOPES
    assert requestable_scopes_for(None) == MONITOR_REQUESTABLE_SCOPES
    # Not a substring or prefix match: a scope that merely looks like admin is not admin.
    assert requestable_scopes_for(["provider:admin-readonly"]) == MONITOR_REQUESTABLE_SCOPES


def test_the_monitor_set_is_read_only():
    """A write-shaped scope reaching this set is the escalation §7b exists to prevent, and
    it would arrive as a one-word edit that looks harmless in review."""
    assert MONITOR_REQUESTABLE_SCOPES == frozenset({"devices:read", "metrics:read"})
    assert all(s.endswith(":read") for s in MONITOR_REQUESTABLE_SCOPES)


def test_the_console_offers_exactly_what_the_bff_permits():
    """The drift guard. The console's MONITOR_SCOPES and this module's own set are written
    in two languages in two repositories' worth of build; the lab finding *was* the two
    disagreeing. Asserting they match is cheaper than finding out in a browser again."""
    panel = pathlib.Path(__file__).resolve().parents[2] / "web" / "src" / "components" / "SupportRequestPanel.tsx"
    if not panel.exists():  # the BFF is packaged and tested without the web tree beside it
        pytest.skip("web/ not present in this checkout")
    match = re.search(r"const MONITOR_SCOPES = (\[[^\]]*\])", panel.read_text())
    assert match, "SupportRequestPanel.tsx no longer declares MONITOR_SCOPES"
    assert set(json.loads(match.group(1))) == set(MONITOR_REQUESTABLE_SCOPES)
