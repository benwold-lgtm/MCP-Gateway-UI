# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The console's own registration form, relayed against a gateway that refuses what the real
one refuses (LR-50's double, applied to the hand-typed path).

`test_tenant_catalog_claim.py` covers the body the BFF *assembles* from a catalog version.
This covers the body a human assembles in `DeviceForm.tsx` — a path that had never been checked
against the gateway's rules at all, and which acquired two new ways to break them the moment the
form learned to register an MCP server:

* `upstream_transport` is refused on an OpenAPI device **on the presence of the key**, so a
  form that helpfully sent the correct default would break every OpenAPI registration. That is
  LR-48 exactly, and LR-48 shipped for three weeks.
* `spec_url` is refused alongside `upstream_kind: "mcp"`, and on a PUT an **absent** `spec_url`
  preserves the stored one — so a form that merely stops showing the field converts nothing and
  refuses everything.

**Why a shared fixture rather than a literal here.** Both of those are contract disagreements
between two processes, and a suite on either side proves nothing about them on its own: the web
suite has no gateway rules and this one has no form. So the bodies live in
`contract/console-device-registration.json`, the web suite asserts the form emits them, and this
suite asserts a faithful gateway accepts them. Transcribing them into both languages instead
would rebuild the gap the fixture exists to close.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402
from tests.gateway_contract import ContractGateway, check_registration  # noqa: E402

# Resolved from this file, not from the working directory: pytest is run from `bff/` in CI but
# from the repo root by hand, and a fixture that only loads one of those ways is a fixture that
# quietly stops being checked.
_FIXTURE = Path(__file__).resolve().parents[2] / "contract" / "console-device-registration.json"
CASES: dict = json.loads(_FIXTURE.read_text())["cases"]


@pytest.fixture()
def console(monkeypatch, tmp_path):
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    app = create_app()
    with TestClient(app) as c:
        assert c.post("/auth/login", json={"password": "admin-pw"}).status_code == 200
        yield c, app


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_form_body_is_one_the_gateway_would_accept(console, name):
    """Every body the console's register form can produce, through the BFF, to a double that
    enforces `registry/validation.py`."""
    client, app = console
    gateway = ContractGateway()
    app.state.gateway.request = gateway.request

    resp = client.post("/api/devices", json=CASES[name]["payload"])

    assert resp.status_code == 201, f"the gateway refused {name}: {gateway.refusals}"
    assert gateway.refusals == []


def test_the_relay_does_not_edit_the_body_on_the_way_through():
    """`POST /api/devices` forwards verbatim, which is the assumption the fixture rests on.

    Asserted directly rather than inferred from the tests above: if the BFF ever started
    adding or dropping a field, those would still pass while the fixture stopped describing
    what the gateway actually receives.
    """
    import inspect

    from app.routers import api

    source = inspect.getsource(api.register_device)
    assert "json=body" in source, "POST /devices no longer relays the request body unchanged"


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_double_is_still_enforcing_for_this_case(name):
    """Guards the guard, per case. A double that stopped refusing would leave every test above
    passing for the reason the old permissive fake did."""
    body = dict(CASES[name]["payload"])
    assert check_registration(body) is None

    if body.get("upstream_kind") == "mcp":
        # The rule the mcp case exists to defend: a stored spec_url carried forward.
        assert check_registration({**body, "spec_url": "https://x/openapi.json"}) is not None
    else:
        # The LR-48 rule: presence, not value.
        assert check_registration({**body, "upstream_transport": "http"}) is not None
