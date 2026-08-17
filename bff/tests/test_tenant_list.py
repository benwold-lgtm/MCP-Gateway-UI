# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The tenant list: the estate the directory published, and what this console can reach.

Two properties carry this file, and they pull in opposite directions:

* The list must be **useful** — an operator staring at a blank text box has to guess tenant
  ids, and a guess that lands on a real customer is a support call at best.
* The list must **authorize nothing**. ADR-0013 §11c puts the entitlement intersection on the
  gateway precisely because the BFF is the side that *chose* the tenant. The moment this list
  starts refusing things, the console has become an authorization point that an attacker
  controls both halves of, and the gateway's check looks redundant to the next reader.

So the load-bearing test here is not "the list is correct" — it is
:func:`test_the_list_offers_but_never_authorizes`, which proves a tenant absent from the list
is still accepted by `authorize`. Everything else is navigation.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.grants import entitled_tenants
from app.main import create_app
from app.security import (
    PLANE_PROVIDER,
    PLANE_TENANT,
    SCOPE_PROVIDER_ADMIN,
    SCOPE_PROVIDER_MONITOR,
)

TENANT = "acme"
OTHER = "globex"
PROVIDER_ISS = "https://provider-idp.example.com"
WHY = "ticket INC-5120: checking whether the fleet poller recovered overnight"


# --- the reader, in isolation -------------------------------------------------
#
# The three-way return is the whole design, so it is tested as three cases rather than as
# "truthy/falsy". `None` and `[]` are both falsy, and a reader that collapsed them would
# pass every assertion phrased as `assert not result`.


def test_a_published_estate_is_returned_in_order():
    """The baseline. Without it, every negative below could pass on a function that always
    returns `None`."""
    assert entitled_tenants([TENANT, OTHER]) == [TENANT, OTHER]


def test_a_single_entitlement_may_arrive_as_a_bare_string():
    """Real IdPs emit a one-element multivalued claim as a scalar. Keycloak's own group
    mapper does it, and the gateway's `_check_entitlement` handles the same shape."""
    assert entitled_tenants(TENANT) == [TENANT]


def test_an_absent_claim_is_not_an_empty_estate():
    """`None` means "this login did not say", which is a *mapper* problem. `[]` means "the
    directory says none", which is an *entitlement* problem. Different fixes, so the console
    must be able to tell them apart — and this is the assertion that stops a later
    simplification from returning `[]` for both."""
    assert entitled_tenants(None) is None
    assert entitled_tenants([]) == []
    assert entitled_tenants(None) is not entitled_tenants([])


@pytest.mark.parametrize("claim", [42, True, {"tenant": TENANT}, object()])
def test_a_claim_of_the_wrong_type_reads_as_unpublished(claim):
    """Not "entitled to nothing": the BFF has no idea what the IdP meant, and saying "you
    are entitled to no tenants" would be inventing an answer. Same fail-direction the
    gateway takes for the same claim, for the same reason."""
    assert entitled_tenants(claim) is None


def test_unusable_names_are_dropped_rather_than_offered():
    """A name `authorize` would refuse is a dead control. Dropping is safe *here* only
    because the list is navigation — it can hide an option, never create authority."""
    assert entitled_tenants([TENANT, "not a tenant!", "", None, 7, OTHER]) == [TENANT, OTHER]


def test_a_claim_that_names_only_junk_is_an_empty_estate_not_an_unpublished_one():
    """The directory *did* answer; nothing it said was usable. That is still an answer, so
    it must not be reported as "no mapper configured"."""
    assert entitled_tenants(["not a tenant!", ""]) == []


def test_duplicates_collapse_and_order_survives():
    assert entitled_tenants([OTHER, TENANT, OTHER, TENANT]) == [OTHER, TENANT]


# --- through the app ----------------------------------------------------------


def _provider_session(**over) -> dict:
    sess = {
        "kind": "oidc",
        "plane": PLANE_PROVIDER,
        "sub": "u-provider-1",
        "provider_scopes": [SCOPE_PROVIDER_ADMIN],
        "entitled_tenants": [TENANT, OTHER],
    }
    sess.update(over)
    return sess


def _console_env(monkeypatch, tmp_path) -> None:
    # Set here rather than relied on from another test module: `_seed_session` needs a real
    # password login to mint a real sid, and the sibling files that happen to set this at
    # import time make the suite pass in aggregate while this file alone would 401.
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "admin-pw")
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", TENANT)
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)


@pytest.fixture
def console(monkeypatch, tmp_path):
    _console_env(monkeypatch, tmp_path)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _seed_session(client, app, data: dict) -> None:
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    live = app.state.sessions._data
    assert len(live) == 1, f"expected exactly one live session, found {len(live)}"
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, dict(data))


def _stored(app) -> dict:
    return next(iter(app.state.sessions._data.values()))[1]


def test_the_route_reports_the_estate_and_what_this_console_serves(console):
    client, app = console
    _seed_session(client, app, _provider_session())

    body = client.get("/provider/tenants").json()
    assert body["entitled"] == [TENANT, OTHER]
    # The second fact, and the one an operator cannot otherwise see: of the two tenants they
    # are entitled to, this deployment *is* only one of them.
    assert body["served"] == TENANT


def test_an_unpublished_estate_survives_the_route_as_null(console):
    """The route is the only place `None` could quietly become `[]` — FastAPI serialises
    both, and a dict `.get()` on a missing key returns `None` either way. Pinned because the
    console renders a different sentence for each."""
    client, app = console
    _seed_session(client, app, _provider_session(entitled_tenants=None))
    assert client.get("/provider/tenants").json()["entitled"] is None


def test_an_empty_estate_survives_the_route_as_an_empty_list(console):
    client, app = console
    _seed_session(client, app, _provider_session(entitled_tenants=[]))
    assert client.get("/provider/tenants").json()["entitled"] == []


def test_a_session_written_before_this_existed_reads_as_unpublished(console):
    """An operator signed in when the BFF is upgraded has no such key. Reading that as "no
    tenants" would tell them their entitlement was revoked; reading it as "unpublished"
    tells them to sign in again, which is the true remedy."""
    client, app = console
    sess = _provider_session()
    del sess["entitled_tenants"]
    _seed_session(client, app, sess)
    assert client.get("/provider/tenants").json()["entitled"] is None


def test_the_list_offers_but_never_authorizes(console):
    """**The one that matters.** A tenant the directory never published is still accepted.

    §11c: the request may *select* a tenant, only the IdP may *authorize* one — and the
    intersection is checked by the gateway, not by the side that built the request. If this
    test ever fails, the BFF has started enforcing entitlement, which sounds like defence in
    depth and is really the caller validating its own input: a compromised console would
    simply lie about the list.

    So the correct behaviour is the uncomfortable-looking one — the act is granted here, and
    is refused later by something the console does not control.
    """
    client, app = console
    _seed_session(client, app, _provider_session(entitled_tenants=[]))

    resp = client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    assert resp.status_code == 200, resp.text
    assert resp.json()["tenant"] == TENANT


def test_being_entitled_does_not_make_an_unserved_tenant_reachable(console):
    """The other direction, and the reason the console annotates the list rather than
    trusting it: `globex` is genuinely in this operator's estate, the act is genuinely
    granted — and the data plane still refuses, because this deployment is not that tenant.

    Without this, the picker would look like a list of places you can go.
    """
    client, app = console
    _seed_session(client, app, _provider_session())

    assert client.post(f"/provider/tenants/{OTHER}/authorize", json={"justification": WHY}).status_code == 200
    resp = client.get("/api/overview")
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(
    "session, expected",
    [
        (_provider_session(provider_scopes=[SCOPE_PROVIDER_MONITOR]), 403),
        ({"kind": "oidc", "plane": PLANE_TENANT, "sub": "u-tenant-1", "role": "admin"}, 403),
    ],
    ids=["provider-monitor-only", "tenant-plane"],
)
def test_the_estate_is_provider_admin_only(console, session, expected):
    """A tenant session must not learn which other tenants a provider operator can reach —
    that list is the provider's customer roster. Same wall as every other route here, in the
    same direction, and worth its own assertion because this one returns data rather than
    performing an act."""
    client, app = console
    _seed_session(client, app, session)
    assert client.get("/provider/tenants").status_code == expected


def test_the_login_stores_the_estate_from_the_configured_claim(console, monkeypatch):
    """Driven through the real callback rather than a seeded session.

    The capture is one line in `provider_callback`. Seeded fixtures would keep every
    assertion above green while a real login stored nothing at all — which is exactly how
    this console shipped an empty Devices view once already.
    """
    client, app = console

    class _FakeProviderIdP:
        async def authorization_url(self, *, state, nonce, challenge):
            return f"{PROVIDER_ISS}/authorize?state={state}"

        async def exchange_code(self, *, code, verifier):
            return {"id_token": "id.tok.sig", "access_token": "operator-access-token"}

        async def validate_id_token(self, *, id_token, nonce, access_token=None):
            return {
                "sub": "u-provider-1",
                "name": "Pat",
                "groups": ["provider-support"],
                "mcp_allowed_tenants": [TENANT, OTHER],
                "nonce": nonce,
            }

    app.state.provider_oidc = _FakeProviderIdP()
    resp = client.get("/auth/provider/login", follow_redirects=False)
    state = resp.headers["location"].split("state=")[1]
    assert client.get(f"/auth/provider/callback?code=abc&state={state}", follow_redirects=False).status_code == 302

    assert _stored(app)["entitled_tenants"] == [TENANT, OTHER]


def test_the_claim_name_is_configurable(monkeypatch, tmp_path):
    """The gateway lets each issuer name its own entitlement claim (`entitlement_claim`), so
    a BFF hardcoded to `mcp_allowed_tenants` would silently publish an empty estate against
    any IdP the gateway is already configured for."""
    _console_env(monkeypatch, tmp_path)
    monkeypatch.setenv("PROVIDER_ENTITLEMENT_CLAIM", "urn:corp:tenants")
    app = create_app()

    class _FakeProviderIdP:
        async def authorization_url(self, *, state, nonce, challenge):
            return f"{PROVIDER_ISS}/authorize?state={state}"

        async def exchange_code(self, *, code, verifier):
            return {"id_token": "id.tok.sig", "access_token": "operator-access-token"}

        async def validate_id_token(self, *, id_token, nonce, access_token=None):
            return {
                "sub": "u-provider-1",
                "groups": ["provider-support"],
                # The default name is present and carries a *different* answer, so a reader
                # that ignored the configured name would still find something and pass.
                "mcp_allowed_tenants": ["wrong-claim"],
                "urn:corp:tenants": [OTHER],
                "nonce": nonce,
            }

    with TestClient(app) as client:
        client.post("/auth/login", json={"password": "admin-pw"})
        app.state.provider_oidc = _FakeProviderIdP()
        resp = client.get("/auth/provider/login", follow_redirects=False)
        state = resp.headers["location"].split("state=")[1]
        client.get(f"/auth/provider/callback?code=abc&state={state}", follow_redirects=False)
        assert _stored(app)["entitled_tenants"] == [OTHER]
