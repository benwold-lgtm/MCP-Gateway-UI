# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0013 §4/§8 — act-on-tenant: cross-tenant power exercised, not held.

**Written before the implementation, deliberately** — the same discipline as
`test_plane_isolation.py` and the gateway's `test_elevated_grants.py`, and for the same
reason: every property here fails *silently*. The request succeeds, the page renders, and
the only symptom is that a provider operator held authority over a customer's stack for
longer, or over more tenants, than anyone authorised.

§4 is one sentence — *acting on a tenant is a discrete, audited, time-boxed act, not
ambient authority for the session's life* — and §8 gives it three rules without which the
sentence is decorative. Each of those rules has an obvious implementation that breaks it:

1. **One tenant at a time.** The natural store for "which tenants may I act on" is a dict
   keyed by tenant, and that is precisely §4 defeated by accumulation: hold three grants
   and you have ambient estate-wide authority assembled one justified act at a time.
2. **Renewal is a new act, not an extension.** The natural implementation of "re-authorize"
   is to find the live grant and push its expiry out. That is a sliding window with extra
   steps — and a sliding window never expires for someone who keeps working, which is
   exactly an attacker's profile.
3. **The window is absolute, so using the grant must not renew it.** The natural place to
   get this wrong is the *read* path, where a helper that refreshes on access looks like
   good hygiene.

Two more the ADR implies rather than states, and which have bitten this project before:

4. **The deadline is stamped at mint time, not recomputed.** Recomputing `granted_at +
   settings.lifetime` means raising the configured lifetime retroactively extends every
   live grant — a config edit silently reaching backwards into grants already issued.
5. **A justification that is never checked is decoration.** §8 says *assert the tenant and
   a justification*; an empty string satisfying that is the same shape as a default read as
   a measurement.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.grants import (  # noqa: E402
    DEFAULT_ACT_ON_TENANT_SECONDS,
    ActOnTenant,
    GrantError,
    active_grant,
    authorize_act_on_tenant,
    release_act_on_tenant,
)
from app.main import create_app  # noqa: E402
from app.security import (  # noqa: E402
    PLANE_PROVIDER,
    PLANE_TENANT,
    SCOPE_PROVIDER_ADMIN,
    SCOPE_PROVIDER_MONITOR,
)

TENANT = "acme"
PROVIDER_ISS = "https://provider-idp.example.com"
WHY = "ticket INC-4471: device sh-01 stopped reporting after a firmware roll"


# --- the mechanism, in isolation ----------------------------------------------


def _provider_session(**over) -> dict:
    sess = {
        "kind": "oidc",
        "plane": PLANE_PROVIDER,
        "sub": "u-provider-1",
        "provider_scopes": [SCOPE_PROVIDER_ADMIN],
    }
    sess.update(over)
    return sess


def test_a_grant_names_one_tenant_and_carries_its_justification():
    """The baseline every negative below is measured against. Without it, a test showing a
    second tenant drops the first proves nothing — the grant might never have existed."""
    sess = _provider_session()
    grant = authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    assert grant.tenant == TENANT
    assert grant.justification == WHY
    assert grant.id
    assert grant.expires_at == 1000.0 + DEFAULT_ACT_ON_TENANT_SECONDS
    assert active_grant(sess, now=1000.0) == grant


def test_acquiring_a_second_tenant_drops_the_first():
    """§8 rule 1, and the one an obvious implementation walks straight into.

    A dict keyed by tenant is the natural store for "which tenants may I act on", and it
    rebuilds ambient estate-wide authority by accumulation — §4 defeated in detail rather
    than honoured. Asserted on the *first* tenant being gone, not merely on the second
    being present: an implementation that appends satisfies the weaker check.
    """
    sess = _provider_session()
    authorize_act_on_tenant(sess, tenant="acme", justification=WHY, now=1000.0)
    authorize_act_on_tenant(sess, tenant="globex", justification="ticket INC-9", now=1001.0)

    live = active_grant(sess, now=1002.0)
    assert live is not None and live.tenant == "globex"
    # ...and nothing anywhere in the session still speaks for acme. Checked against the
    # serialised session rather than the accessor, because an accessor that returns the
    # newest of several would pass while the session still carried both.
    assert "acme" not in repr(sess)


def test_re_authorizing_the_same_tenant_mints_a_new_act():
    """§8 rule 2. "Renewal is a new act, not an extension" — so re-authorizing must produce
    a NEW grant id and record the NEW justification, not find the live grant and push its
    expiry out. The extension reading is indistinguishable from a sliding window, and a
    sliding window never expires for someone who keeps working."""
    sess = _provider_session()
    first = authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    second = authorize_act_on_tenant(sess, tenant=TENANT, justification="ticket INC-4472", now=1500.0)

    assert second.id != first.id
    assert second.justification == "ticket INC-4472"
    assert second.expires_at == 1500.0 + DEFAULT_ACT_ON_TENANT_SECONDS


def test_using_a_grant_does_not_extend_it():
    """§8's absolute window, on the read path — where a helper that refreshes on access
    looks like good hygiene and is the whole bug. The deadline after a hundred reads must
    be the deadline it was minted with."""
    sess = _provider_session()
    grant = authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    for tick in range(100):
        assert active_grant(sess, now=1000.0 + tick) == grant
    assert active_grant(sess, now=1000.0 + 99).expires_at == grant.expires_at


def test_a_grant_past_its_window_is_gone():
    sess = _provider_session()
    authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    assert active_grant(sess, now=1000.0 + DEFAULT_ACT_ON_TENANT_SECONDS - 1) is not None
    assert active_grant(sess, now=1000.0 + DEFAULT_ACT_ON_TENANT_SECONDS) is None
    assert active_grant(sess, now=1000.0 + DEFAULT_ACT_ON_TENANT_SECONDS + 3600) is None


def test_the_deadline_is_stamped_at_mint_time_not_recomputed():
    """Hazard 4. If expiry is derived as `granted_at + configured_lifetime` on every read,
    raising the configured lifetime reaches backwards and extends every grant already
    issued — a config edit quietly re-authorising acts nobody re-authorised."""
    sess = _provider_session()
    authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0, lifetime=60)
    assert active_grant(sess, now=1059.0) is not None
    # The same session read under a *longer* configured lifetime. The stored deadline is
    # what counts, and there is no argument here to change it.
    assert active_grant(sess, now=1061.0) is None


def test_a_shorter_lifetime_is_honoured_and_zero_is_refused():
    """Durations are configuration; the relationships are the decision (§8). A zero or
    negative lifetime is refused rather than minting a grant that is dead on arrival — an
    operator who misconfigures it should see a refusal, not an unexplained 403 later."""
    sess = _provider_session()
    grant = authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0, lifetime=30)
    assert grant.expires_at == 1030.0
    for bad in (0, -1):
        with pytest.raises(GrantError, match="lifetime"):
            authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0, lifetime=bad)


def test_a_justification_is_required_and_must_say_something():
    """Hazard 5. §8: *assert the tenant and a justification*. A field that accepts an empty
    string is decoration, and this one is the only record of **why** a customer's stack was
    touched — the question an audit is actually asked afterwards."""
    sess = _provider_session()
    for empty in ("", "   ", "\t\n", None):
        with pytest.raises(GrantError, match="justification"):
            authorize_act_on_tenant(sess, tenant=TENANT, justification=empty, now=1000.0)
    assert active_grant(sess, now=1000.0) is None


def test_an_oversized_justification_is_refused_not_truncated():
    """It lands in a hash-chained audit record, so it is unbounded input reaching an
    append-only structure. Refused rather than silently truncated: a justification the
    operator wrote and the record does not contain is worse than no record, because it
    reads as complete."""
    sess = _provider_session()
    with pytest.raises(GrantError, match="justification"):
        authorize_act_on_tenant(sess, tenant=TENANT, justification="x" * 5000, now=1000.0)


def test_a_tenant_name_must_be_plausible():
    """The tenant is a discriminator, not free text: it is compared against this
    deployment's own identity to decide whether a request may proceed. Rejecting odd shapes
    at the door keeps that comparison about identity rather than about normalisation."""
    sess = _provider_session()
    for bad in ("", "  ", None, "a b", "../etc", "x" * 200, 7):
        with pytest.raises(GrantError, match="tenant"):
            authorize_act_on_tenant(sess, tenant=bad, justification=WHY, now=1000.0)


def test_only_a_provider_session_with_provider_admin_may_authorize():
    """§7: `provider:monitor` is the estate-health scope and holds **no tenant API access
    at all**, so it must not be able to mint the grant that produces some. And a tenant
    session must not mint one however its own IdP names its groups (§5/§6a)."""
    monitor_only = _provider_session(provider_scopes=[SCOPE_PROVIDER_MONITOR])
    with pytest.raises(GrantError, match="provider:admin"):
        authorize_act_on_tenant(monitor_only, tenant=TENANT, justification=WHY, now=1000.0)

    tenant_sess = {"kind": "oidc", "plane": PLANE_TENANT, "sub": "u-1", "provider_scopes": [SCOPE_PROVIDER_ADMIN]}
    with pytest.raises(GrantError, match="provider-plane"):
        authorize_act_on_tenant(tenant_sess, tenant=TENANT, justification=WHY, now=1000.0)


def test_a_grant_forged_onto_a_tenant_session_is_never_active():
    """The read path's half of the rule above. §3 fixes the plane at login, so this state
    should be unreachable — but `active_grant` is what stands between a session and a
    customer's data plane, and it must not depend on the writer having been careful. A
    shared session store is the topology where a session from one population can be
    presented to a process serving the other."""
    forged = {
        "kind": "oidc",
        "plane": PLANE_TENANT,
        "sub": "u-1",
        "act_on_tenant": {
            "id": "g-forged",
            "tenant": TENANT,
            "justification": WHY,
            "granted_at": 1000.0,
            "expires_at": 9_999_999_999.0,
        },
    }
    assert active_grant(forged, now=1000.0) is None


def test_a_malformed_stored_grant_reads_as_no_grant():
    """Fail closed on junk. A grant is a plain dict in a shared store, so the reader must
    treat a missing or wrong-typed field as *no authority* rather than raising into a 500
    — which would turn a corrupted session into an outage instead of a re-authorization."""
    junk = [
        "nonsense",
        42,
        [],
        {},
        {"tenant": TENANT},
        {"expires_at": "soon", "tenant": TENANT, "id": "g"},
    ]
    # Each case above is rejected by the *first* guard it meets, which means none of them
    # ever reaches the clock fields — so a well-formed grant with a junk deadline has to be
    # listed explicitly. Leaving it out is the fixture-starts-past-the-bug shape this
    # project keeps hitting: the guard nearest the failure is the one never exercised.
    well_formed = {"id": "g-1", "tenant": TENANT, "justification": WHY, "granted_at": 1000.0}
    junk += [
        {**well_formed, "expires_at": "soon"},
        {**well_formed, "expires_at": None},
        {**well_formed, "expires_at": True},  # bool is an int; a deadline of True is not 1.0
        {**well_formed, "granted_at": "then", "expires_at": 9_999_999_999.0},
    ]
    for case in junk:
        sess = _provider_session(act_on_tenant=case)
        assert active_grant(sess, now=1000.0) is None, case


def test_releasing_drops_the_grant():
    """Ending an act deliberately is the cheap half of §4 — an operator who has finished
    should not carry the authority for the rest of the hour."""
    sess = _provider_session()
    authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    released = release_act_on_tenant(sess)
    assert released is not None and released.tenant == TENANT
    assert active_grant(sess, now=1000.0) is None
    assert release_act_on_tenant(sess) is None  # idempotent


def test_a_grant_confers_no_elevated_scope():
    """§5a/§8: the two elevated grants are separate acts behind a step-up. Holding
    act-on-tenant is the *everyday* debugging motion, and it must not carry `tools:call` or
    credential access with it — that conflation is exactly what §5a exists to prevent."""
    sess = _provider_session()
    grant = authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    assert not hasattr(grant, "scopes")
    assert sorted(sess["provider_scopes"]) == [SCOPE_PROVIDER_ADMIN]


def test_a_grant_round_trips_through_a_plain_dict():
    """The session store is Redis in every deployment that matters, so the grant has to
    survive JSON. Pinned because an implementation holding a dataclass on the session works
    perfectly against the in-memory store and fails only in production."""
    import json

    sess = _provider_session()
    grant = authorize_act_on_tenant(sess, tenant=TENANT, justification=WHY, now=1000.0)
    revived = json.loads(json.dumps(sess))
    assert active_grant(revived, now=1000.0) == grant
    assert isinstance(revived["act_on_tenant"], dict)


# --- through the app: the routes, the audit, and the data-plane wall ----------


def _console_env(monkeypatch, tmp_path, *, tenant_id: str | None = TENANT) -> None:
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", TENANT)
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    if tenant_id is None:
        monkeypatch.delenv("TENANT_ID", raising=False)
    else:
        monkeypatch.setenv("TENANT_ID", tenant_id)


@pytest.fixture
def console(monkeypatch, tmp_path):
    """A provider console that also knows which tenant this deployment serves.

    `TENANT_ID` is the discriminator the data-plane gate compares a grant against, and it
    mirrors the gateway's own `gateway.tenant_id` (ADR-0013 §11) deliberately — one name
    for one concept across both halves.
    """
    _console_env(monkeypatch, tmp_path)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _audited(app, action: str) -> list[dict]:
    """The `action` records from the chain, oldest first — read back through the real
    reader rather than a spy, so the assertions cover sealing and framing too."""
    rows = app.state.audit.read(tenant=TENANT, limit=200)
    return [r["content"] for r in reversed(rows) if r["content"] and r["content"]["action"] == action]


def _seed_session(client, app, data: dict) -> None:
    """Swap this client's session content, keeping the app's real cookie plumbing.

    Same helper as `test_plane_isolation.py`: a password login mints a real sid and cookie,
    then the stored content becomes the session under test. The cookie/sid path stays real
    while the test is about what a session may *do* once it exists.
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


def _stored(app) -> dict:
    live = app.state.sessions._data
    return next(iter(live.values()))[1]


def test_the_route_mints_a_grant_and_audits_the_justification(console):
    client, app = console
    _seed_session(client, app, _provider_session())

    resp = client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tenant"] == TENANT and body["id"] and body["expires_at"]
    # The justification is not echoed back to the browser — it is evidence, it is already
    # in the chain, and the operator who wrote it seconds ago does not need it read back.
    # Asserted rather than left as a comment: echoing it makes it a field some later view
    # renders, caches or logs a second time, and nothing else here would notice.
    assert "justification" not in body
    assert WHY not in resp.text
    # What matters is that it reached the chain.
    records = _audited(app, "provider.act_on_tenant.authorize")
    assert len(records) == 1
    assert records[0]["target"] == TENANT
    assert records[0]["outcome"] == "success"
    assert records[0]["detail"]["justification"] == WHY
    assert records[0]["detail"]["grant"] == body["id"]


def test_a_refused_authorization_is_audited_too(console):
    """ "Who was refused what" is the question an audit is most often asked. A provider
    operator attempting to act without a justification is exactly the record worth having,
    and it is the one an implementation that audits only successes drops."""
    client, app = console
    _seed_session(client, app, _provider_session())

    resp = client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": "  "})
    assert resp.status_code == 400
    denied = [r for r in _audited(app, "provider.act_on_tenant.authorize") if r["outcome"] == "denied"]
    assert len(denied) == 1
    assert denied[0]["target"] == TENANT


def test_each_re_authorization_writes_its_own_record(console):
    """§8: renewal is a new act. Two acts, two records — an implementation that treats the
    second as a no-op because a grant is already live leaves the second justification
    nowhere."""
    client, app = console
    _seed_session(client, app, _provider_session())

    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": "ticket INC-4472"})

    records = _audited(app, "provider.act_on_tenant.authorize")
    assert [r["detail"]["justification"] for r in records] == [WHY, "ticket INC-4472"]
    assert records[0]["detail"]["grant"] != records[1]["detail"]["grant"]


def test_switching_tenants_is_audited_as_dropping_the_first(console):
    """The accumulation rule, made visible. A reader of the chain has to be able to see
    that authority over `acme` ended — otherwise the record shows two grants opening and
    none closing, which reads exactly like the ambient authority §4 forbids."""
    client, app = console
    _seed_session(client, app, _provider_session())

    client.post("/provider/tenants/acme/authorize", json={"justification": WHY})
    client.post("/provider/tenants/globex/authorize", json={"justification": "ticket INC-9"})

    dropped = _audited(app, "provider.act_on_tenant.release")
    assert len(dropped) == 1
    assert dropped[0]["target"] == "acme"
    assert dropped[0]["detail"]["reason"] == "superseded"


def test_the_current_grant_is_readable_and_the_release_route_ends_it(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})

    assert client.get("/provider/act-on-tenant").json()["tenant"] == TENANT
    assert client.delete("/provider/act-on-tenant").status_code == 200
    assert client.get("/provider/act-on-tenant").json() == {"grant": None}
    released = _audited(app, "provider.act_on_tenant.release")
    assert released and released[-1]["detail"]["reason"] == "released"


def test_a_monitor_only_session_is_refused_by_the_route(console):
    client, app = console
    _seed_session(client, app, _provider_session(provider_scopes=[SCOPE_PROVIDER_MONITOR]))
    resp = client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    assert resp.status_code == 403


def test_a_tenant_session_cannot_reach_the_authorize_route(console):
    """The converse direction, which matters just as much: the route is provider-plane, and
    a break-glass password session (tenant plane) must not reach it."""
    client, app = console
    _seed_session(client, app, {"kind": "password", "role": "admin", "plane": PLANE_TENANT})
    resp = client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    assert resp.status_code == 403


# --- the wall this grant is the key to ----------------------------------------


# Every test below seeds a session that already holds a credential, so the ONLY variable
# is the grant. Without that the credential refusal added alongside these tests answers
# first, every assertion collapses to "something said 403", and the tenant discriminator
# stops being tested at all — a downstream backstop masking the control under test. Each
# one therefore asserts on the *reason*, not on the status code.


def test_without_a_grant_a_provider_session_is_still_refused_the_data_plane(console):
    """The state before slice 2 — asserted, not assumed. If this passes only because the
    grant machinery is missing, the tests below prove nothing about the gate."""
    client, app = console
    _seed_session(client, app, _provider_session(access_token="provider-operator-token"))
    resp = client.get("/api/devices")
    assert resp.status_code == 403
    assert "act on tenant" in resp.text


def test_a_live_grant_for_this_tenant_opens_the_data_plane(console):
    """A grant plus a credential of the session's own gets through — and the credential
    that reaches the gateway is **the operator's**, not the stack's admin key.

    The bearer is asserted, not the status. The first version of this test stubbed
    `gateway.get` and checked for a 200, which passed while the BFF was relaying the tenant
    stack's admin token: `upstream_bearer` returned `None` for a provider session and the
    GatewayClient's *default* Authorization header applied. A provider operator arriving at
    the tenant gateway as gateway `admin` is above the §5a ceiling, carries `tools:call` and
    every `backup:*` with no step-up, and lands in the tenant's audit as a shared key rather
    than a human — the exact outcome the second-issuer design exists to replace. Stubbing
    the call while ignoring its most important argument is what hid it.
    """
    client, app = console
    _seed_session(client, app, _provider_session(access_token="provider-operator-token"))
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})

    seen = {}

    async def _spy(path, bearer=None, **kw):
        import httpx

        seen["bearer"] = bearer
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _spy
    assert client.get("/api/devices").status_code == 200
    assert seen["bearer"] == "provider-operator-token"
    assert seen["bearer"] != app.state.settings.gateway_token


def test_a_provider_session_is_never_relayed_with_the_stacks_admin_key(console):
    """The defect this pair exists for, stated directly. A provider session with a live
    grant but no credential of its own must be refused at the gate — because `None` does not
    mean "no credential" to the GatewayClient, it means "use the admin key"."""
    client, app = console
    _seed_session(client, app, _provider_session())  # no access_token
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})

    reached = []

    async def _spy(path, bearer=None, **kw):
        import httpx

        reached.append(bearer)
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _spy
    resp = client.get("/api/devices")
    assert resp.status_code == 403
    # The *gate's* wording, not `upstream_bearer`'s. The two refusals are deliberate
    # defence in depth and both mention the admin key, so matching the shared phrase would
    # let either one stand in for the other and neither would be independently tested.
    assert "holds no credential for this tenant's gateway" in resp.text
    assert reached == [], "a provider session reached the gateway with the stack's admin key"


async def test_upstream_bearer_refuses_a_provider_session_with_no_token():
    """The second layer, tested at its own level. `require_role` already refuses this case,
    so a route-level test cannot tell the two apart — and a backstop that hides the control
    beneath it is how a removed check goes unnoticed. Called directly for that reason.

    What makes `None` dangerous here is that it does not mean "no credential" to the
    GatewayClient: it means "fall back to the configured admin token".
    """
    from fastapi import HTTPException

    from app.security import upstream_bearer

    class _Req:
        def __init__(self, sess):
            self.state = SimpleNamespace(_bff_session=sess)

    with pytest.raises(HTTPException) as exc:
        await upstream_bearer(_Req(_provider_session()))
    assert exc.value.status_code == 403
    assert "admin key" in exc.value.detail
    # ...and the converse, so the guard cannot be "refuse every provider session".
    assert await upstream_bearer(_Req(_provider_session(access_token="tok"))) == "tok"


def test_a_grant_for_a_different_tenant_does_not_open_this_one(console):
    """The discriminator doing its job. A grant is authority over *one named* tenant, and
    this deployment serves exactly one — so a grant naming another opens nothing here. Get
    this wrong and "act on tenant X" becomes "act on any tenant", which is §4 inverted."""
    client, app = console
    _seed_session(client, app, _provider_session(access_token="provider-operator-token"))
    client.post("/provider/tenants/globex/authorize", json={"justification": "ticket INC-9"})
    resp = client.get("/api/devices")
    assert resp.status_code == 403
    assert "act on tenant" in resp.text


def test_an_expired_grant_closes_the_data_plane_again(console):
    """The window is the control, so it has to bite on the path the authority is used."""
    client, app = console
    _seed_session(client, app, _provider_session(access_token="provider-operator-token"))
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})

    stored = _stored(app)
    stored["act_on_tenant"]["expires_at"] = 0.0
    resp = client.get("/api/devices")
    assert resp.status_code == 403
    assert "act on tenant" in resp.text


def test_a_deployment_with_no_tenant_id_admits_nobody(monkeypatch, tmp_path):
    """Fail closed, and the reason an existing tenant stack needs no config change: with no
    `TENANT_ID` there is nothing for a grant to name, so no grant can ever match, and the
    §4 refusal stands exactly as it did before this slice.

    The grant is still *minted* — authorizing is a provider-plane act and does not depend
    on where it will be spent. What must not happen is that it opens a data plane whose
    tenant identity was never configured.
    """
    _console_env(monkeypatch, tmp_path, tenant_id=None)
    app = create_app()
    with TestClient(app) as client:
        _seed_session(client, app, _provider_session(access_token="provider-operator-token"))
        assert client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY}).status_code == 200
        resp = client.get("/api/devices")
        assert resp.status_code == 403
        assert "act on tenant" in resp.text


def test_the_grant_is_not_a_gateway_credential(console):
    """§4/§7, one layer in: the grant is *authorization to proceed*, not a credential.
    Minting one must not conjure an upstream token, and must not alter one the session
    already had — the two are separate facts about a session and the gate checks both."""
    client, app = console
    _seed_session(client, app, _provider_session())
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    assert not _stored(app).get("access_token")

    _seed_session(client, app, _provider_session(access_token="provider-operator-token"))
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    assert _stored(app)["access_token"] == "provider-operator-token"


def test_the_grant_survives_a_store_round_trip_under_its_own_key(console):
    """Named `act_on_tenant`, singular, on the session. Pinned because the plural — or a
    dict keyed by tenant — is the shape that permits accumulation, and a schema test is
    what stops that arriving as an innocuous refactor."""
    client, app = console
    _seed_session(client, app, _provider_session())
    client.post(f"/provider/tenants/{TENANT}/authorize", json={"justification": WHY})
    stored = _stored(app)
    assert isinstance(stored["act_on_tenant"], dict)
    assert stored["act_on_tenant"]["tenant"] == TENANT
    assert ActOnTenant.from_session(stored) is not None
