# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0013 §5a/§8/§11b — the elevated grant, and the step-up behind it.

`provider:credentials` was the other elevated class (single-use, backup:*) and is removed:
ADR-0018 §6 (gateway repo) removed the credential dump it gated. It was this file's only
single-use class, so the end-to-end "spent by one relayed request" coverage that used to run
against it is gone with it — `test_spend_elevated_grant_drops_a_single_use_grant_directly`
covers the generic mechanism at the unit level instead, until a future class needs it again
end-to-end.

**Written before the implementation**, like `test_act_on_tenant.py` and the gateway's own
`test_elevated_grants.py`. Same reason: everything here fails silently. The request
succeeds, the page renders, and the only symptom is that someone invoked a tool on a
customer's hardware, or walked off with their credentials, without the proof §8 requires.

This is the BFF half of the mechanism whose gateway half merged as MCP-Gateway #119. The
division of labour matters, because getting it backwards is how both halves end up trusting
the other to have checked:

* **The provider IdP mints the grant claim** (§11b). Neither the BFF nor the gateway does.
* **The BFF requests the step-up and verifies it happened**, then presents the resulting
  token upstream. It records what it did in its own hash-chained audit.
* **The gateway independently verifies the claim** — window, tenant, single-use consumption
  — and is authoritative. The BFF's checks do not replace the gateway's; they exist because
  the BFF's *audit record* claims a step-up occurred, and a record asserting something the
  writer never checked is worse than no record.

The hazards, each of which the obvious implementation walks into:

1. **Requesting a step-up mistaken for achieving one.** `acr_values` is a *request*
   parameter and an IdP may decline it and issue anyway (§11b constraint 2). The BFF asked;
   that proves nothing. The `acr` in the *issued* token is what counts.
2. **A stale step-up.** An `auth_time` from this morning satisfying an elevation now, which
   is a sliding window wearing an absolute one's clothes.
3. **Elevation without an act.** The elevated grant riding on top of nothing — bypassing
   act-on-tenant's justification, its one-tenant-at-a-time rule and its audit trail.
4. **An elevated credential outliving its grant.** The token is the capability; if it
   survives release, expiry or a tenant switch, the window stopped being the control.
5. **Single use that is not.** A single-use class is one operation (§8). A BFF that keeps
   presenting the token leaves the bound entirely to the gateway's consumption record —
   which works, but means the BFF's own audit says "one operation" while it made several.
   No live class is single-use today; the mechanism (`spend_elevated_grant`) is kept
   generic and tested directly against that hazard for whenever one is.
6. **The provider vocabulary leaking downstream.** `provider:invoke` is a BFF scope. What
   goes to the gateway is `tools:call`. §11 keeps that line, and it is kept *here*, since
   this is the side that does the mapping.
7. **The elevation becoming ambient.** Writing the elevated scope into the session's
   `provider_scopes` would make it a held capability, which is §5a's whole objection.
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.grants import (  # noqa: E402
    ELEVATED_GRANT_SPECS,
    GrantError,
    active_elevated_grant,
    authorize_act_on_tenant,
    elevated_spec,
    record_elevated_grant,
    release_act_on_tenant,
    spend_elevated_grant,
    step_up_scopes,
)
from app.main import create_app  # noqa: E402
from app.security import (  # noqa: E402
    PLANE_PROVIDER,
    PLANE_TENANT,
    SCOPE_PROVIDER_ADMIN,
    SCOPE_PROVIDER_INVOKE,
    SCOPE_PROVIDER_MONITOR,
)

TENANT = "acme"
PROVIDER_ISS = "https://provider-idp.example.com"
STEP_UP_ACR = "urn:mcp:provider:step-up"
WHY = "ticket INC-4471: reproducing the fault on sh-01 needs a live tool call"
OPERATOR_TOKEN = "provider-operator-token"
STEP_UP_TOKEN = "step-up-token-carrying-the-grant-claim"


def _provider_session(**over) -> dict:
    sess = {
        "kind": "oidc",
        "plane": PLANE_PROVIDER,
        "sub": "u-provider-1",
        "provider_scopes": [SCOPE_PROVIDER_ADMIN],
        "access_token": OPERATOR_TOKEN,
    }
    sess.update(over)
    return sess


def _acting(now: float = 1000.0, **over) -> dict:
    """A session already holding a live act-on-tenant grant — the state an elevation
    starts from, since elevation is layered on an act rather than replacing one."""
    sess = _provider_session(**over)
    authorize_act_on_tenant(sess, tenant=TENANT, justification="ticket INC-4471", now=now)
    return sess


def _claim(**over) -> dict:
    claim = {"id": "g-7f2", "tenant": TENANT, "scopes": ["tools:call"], "exp": 1000.0 + 900}
    claim.update(over)
    return claim


def _record(sess, *, now=1000.0, **over):
    args = dict(
        tenant=TENANT,
        provider_scope=SCOPE_PROVIDER_INVOKE,
        justification=WHY,
        claim=_claim(),
        access_token=STEP_UP_TOKEN,
        auth_time=now - 30,
        now=now,
    )
    args.update(over)
    return record_elevated_grant(sess, **args)


# --- §8's elevated class, mapped onto gateway scopes ---------------------------


def test_the_elevated_class_maps_to_gateway_scopes_not_provider_ones():
    """Hazard 6. `provider:invoke` is a BFF scope and the gateway has never heard of it
    (§11). This side owns the mapping, so this is where a leak would start — and the
    gateway would *silently ignore* an unknown scope rather than refuse it, which is why
    the assertion lives here rather than there."""
    invoke = elevated_spec(SCOPE_PROVIDER_INVOKE)
    assert invoke.gateway_scopes == ("tools:call",)
    for spec in ELEVATED_GRANT_SPECS.values():
        for scope in spec.gateway_scopes:
            assert not scope.startswith("provider:")


def test_invoke_is_not_single_use():
    """§8's relationship, which is the decision — the duration is configuration. Was
    compared against `provider:credentials` (removed, ADR-0018 §6) as the one that was;
    nothing left to compare against, so this pins the remaining half on its own."""
    assert elevated_spec(SCOPE_PROVIDER_INVOKE).single_use is False


def test_provider_credentials_is_no_longer_an_elevatable_scope():
    """Locks the removal itself: asking to elevate the retired scope must fail the same
    way any other non-elevated scope does, not be silently accepted or 500."""
    with pytest.raises(GrantError, match="elevat"):
        elevated_spec("provider:credentials")


def test_only_the_elevated_scope_is_elevatable():
    """The closed range. `provider:admin` needs no elevation and `provider:monitor` has no
    tenant access at all — asking to elevate either is a misunderstanding of the model, and
    it fails loudly rather than minting something meaningless."""
    for scope in (SCOPE_PROVIDER_ADMIN, SCOPE_PROVIDER_MONITOR, "tools:call", "", None):
        with pytest.raises(GrantError, match="elevat"):
            elevated_spec(scope)


# --- recording a verified step-up ---------------------------------------------


def test_a_verified_step_up_is_recorded_against_the_act():
    """The baseline. Without it every refusal below could be passing for the wrong reason."""
    sess = _acting()
    grant = _record(sess)
    assert grant.id == "g-7f2"
    assert grant.tenant == TENANT
    assert grant.provider_scope == SCOPE_PROVIDER_INVOKE
    assert grant.gateway_scopes == ("tools:call",)
    assert grant.justification == WHY
    assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) == grant


def test_the_elevated_token_is_held_inside_the_grant():
    """Hazard 4, structurally rather than by discipline. The step-up token *is* the
    capability, so it lives inside the grant record — dropping the grant drops the
    credential, and there is no second place to remember to clear."""
    sess = _acting()
    grant = _record(sess)
    assert grant.access_token == STEP_UP_TOKEN
    release_act_on_tenant(sess)
    assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) is None
    assert STEP_UP_TOKEN not in repr(sess)


def test_elevation_requires_a_live_act_on_that_tenant():
    """Hazard 3. Elevation is layered on an act, not an alternative to one — otherwise it
    routes around act-on-tenant's justification, its one-tenant-at-a-time rule and its
    audit trail, which is §4 bypassed by the very mechanism §8 puts on top of it."""
    bare = _provider_session()
    with pytest.raises(GrantError, match="act"):
        _record(bare)

    other = _provider_session()
    authorize_act_on_tenant(other, tenant="globex", justification="ticket INC-9", now=1000.0)
    with pytest.raises(GrantError, match="act"):
        _record(other)


def test_a_stale_step_up_is_refused():
    """Hazard 2. The freshness bound is the grant's own window — a 15-minute elevation *is*
    a 15-minute step-up freshness requirement, which is the same single mechanism the
    gateway uses. One rule, not two that can drift apart."""
    sess = _acting()
    spec = elevated_spec(SCOPE_PROVIDER_INVOKE)
    with pytest.raises(GrantError, match="auth_time|stale|fresh"):
        _record(sess, auth_time=1000.0 - spec.max_lifetime - 1)


def test_an_auth_time_in_the_future_is_refused():
    """Otherwise the freshness check is defeated from the same place it is enforced."""
    sess = _acting()
    with pytest.raises(GrantError, match="auth_time|future"):
        _record(sess, auth_time=1000.0 + 600)


def test_a_missing_or_junk_auth_time_is_refused():
    sess = _acting()
    for bad in (None, "recently", True, []):
        with pytest.raises(GrantError, match="auth_time"):
            _record(sess, auth_time=bad)


def test_the_window_is_the_bffs_and_the_claim_may_only_shorten_it():
    """The BFF's mirror of §11b constraint 1. The claim's `exp` is the IdP's assertion; the
    window is computed here from `auth_time`. A claim may bring the deadline *in* — an IdP
    with a tighter policy is honoured — but never push it out."""
    sess = _acting()
    spec = elevated_spec(SCOPE_PROVIDER_INVOKE)

    long_claim = _record(sess, claim=_claim(exp=1000.0 + 99999))
    assert long_claim.expires_at == (1000.0 - 30) + spec.max_lifetime

    release_act_on_tenant(sess)
    sess = _acting()
    short = _record(sess, claim=_claim(exp=1000.0 + 60))
    assert short.expires_at == 1000.0 + 60


def test_a_claim_naming_another_tenant_is_refused():
    """The IdP mints the claim, so this is the BFF checking the thing it asked for is the
    thing it got. A grant for globex arriving during an act on acme is either a
    misconfigured hook or a redirected transaction, and neither should be stored."""
    sess = _acting()
    with pytest.raises(GrantError, match="tenant"):
        _record(sess, claim=_claim(tenant="globex"))


def test_a_claim_whose_scopes_are_not_the_ones_requested_is_refused():
    """Asking to elevate `provider:invoke` and being handed `backup:*` is not a narrower
    grant, it is a different one. Refused rather than intersected: a grant that silently
    grants something other than what was asked for is worse than one that fails."""
    sess = _acting()
    with pytest.raises(GrantError, match="scope"):
        _record(sess, claim=_claim(scopes=["backup:read"]))
    with pytest.raises(GrantError, match="scope"):
        _record(sess, claim=_claim(scopes=[]))


def test_a_claim_with_no_id_is_refused():
    """The id is what the audit record and the gateway's consumption both key on."""
    sess = _acting()
    for bad in ({}, {"tenant": TENANT, "scopes": ["tools:call"]}, "nope", 7):
        with pytest.raises(GrantError, match="claim|id"):
            _record(sess, claim=bad)


def test_a_step_up_with_no_access_token_is_refused():
    """An elevation whose token is missing is not a weaker elevation — it is a record with
    no capability, and treating it as live would send the *ordinary* operator token to a
    request the caller believes is elevated.

    Asserted on `record_elevated_grant` directly. The reader refuses a tokenless grant too,
    so a test that only checked `active_elevated_grant` would pass with this check deleted
    — a backstop standing in for the control.
    """
    for bad in (None, "", 7, []):
        sess = _acting()
        with pytest.raises(GrantError, match="access token|token"):
            _record(sess, access_token=bad)


def test_a_claim_that_has_already_expired_is_refused_not_stored():
    """Capping can pull the deadline into the past (§11b constraint 1 lets the claim only
    shorten), and a grant dead on arrival is worse than a refusal: the operator has just
    completed an MFA prompt and would be told it worked, while every subsequent request
    quietly used their ordinary token instead."""
    sess = _acting()
    with pytest.raises(GrantError, match="past|dead"):
        _record(sess, claim=_claim(exp=900.0))
    assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) is None


def test_the_elevation_is_not_written_into_the_sessions_scopes():
    """Hazard 7, and §5a's whole objection. An elevated scope in `provider_scopes` is a
    *held* capability — it would pass `require_provider_scope` for the rest of the session,
    which is the ambient authority the grant exists to replace."""
    sess = _acting()
    _record(sess)
    assert sess["provider_scopes"] == [SCOPE_PROVIDER_ADMIN]
    assert SCOPE_PROVIDER_INVOKE not in sess["provider_scopes"]


# --- the window, and what ends it ----------------------------------------------


def test_an_expired_elevation_is_gone():
    sess = _acting()
    spec = elevated_spec(SCOPE_PROVIDER_INVOKE)
    _record(sess)
    deadline = (1000.0 - 30) + spec.max_lifetime
    assert active_elevated_grant(sess, tenant=TENANT, now=deadline - 1) is not None
    assert active_elevated_grant(sess, tenant=TENANT, now=deadline) is None


def test_using_an_elevation_does_not_extend_it():
    """§8's absolute window again, on the read path."""
    sess = _acting()
    grant = _record(sess)
    for tick in range(50):
        got = active_elevated_grant(sess, tenant=TENANT, now=1000.0 + tick)
        assert got is not None and got.expires_at == grant.expires_at


def test_switching_tenants_drops_the_elevation():
    """Hazard 4, in the shape most likely to be missed. An elevation is authority over one
    tenant's hardware; carrying it into an act on a *different* tenant would let a
    `tools:call` grant obtained for acme be spent on globex."""
    sess = _acting()
    _record(sess)
    authorize_act_on_tenant(sess, tenant="globex", justification="ticket INC-9", now=1010.0)
    assert active_elevated_grant(sess, tenant="globex", now=1010.0) is None
    assert active_elevated_grant(sess, tenant=TENANT, now=1010.0) is None


def test_re_authorizing_the_same_tenant_also_drops_the_elevation():
    """A new act is a new act (§8): its elevation is not inherited. Otherwise "renewal is a
    new act" holds for the act and quietly fails for the more dangerous thing riding on it."""
    sess = _acting()
    _record(sess)
    authorize_act_on_tenant(sess, tenant=TENANT, justification="ticket INC-4472", now=1010.0)
    assert active_elevated_grant(sess, tenant=TENANT, now=1010.0) is None


def test_an_elevation_for_another_tenant_is_never_returned():
    """The read path's discriminator. Belt and braces over the drop above: even if a grant
    for another tenant were somehow stored, asking about *this* tenant must not find it."""
    sess = _acting()
    _record(sess)
    assert active_elevated_grant(sess, tenant="globex", now=1000.0) is None


def test_a_grant_forged_onto_a_tenant_session_is_never_active():
    """The plane wall, on the most valuable thing a session can carry."""
    forged = _acting()
    _record(forged)
    forged["plane"] = PLANE_TENANT
    assert active_elevated_grant(forged, tenant=TENANT, now=1000.0) is None


def test_a_malformed_stored_elevation_reads_as_none():
    """Fail closed on junk, per-guard. Each case below is well-formed up to the field it is
    testing — a list of uniformly broken inputs only ever exercises the first guard, which
    is how the guard nearest the failure goes untested."""
    ok = {
        "id": "g-1",
        "tenant": TENANT,
        "provider_scope": SCOPE_PROVIDER_INVOKE,
        "gateway_scopes": ["tools:call"],
        "justification": WHY,
        "granted_at": 1000.0,
        "expires_at": 9_999_999_999.0,
        "single_use": False,
        "access_token": STEP_UP_TOKEN,
    }
    for case in (
        "nonsense",
        42,
        [],
        {},
        {k: v for k, v in ok.items() if k != "id"},
        {**ok, "expires_at": "soon"},
        {**ok, "expires_at": None},
        {**ok, "granted_at": True},
        {**ok, "access_token": ""},
        {**ok, "access_token": None},
        {**ok, "gateway_scopes": "tools:call"},
    ):
        sess = _acting()
        sess["elevated_grant"] = case
        assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) is None, case


# --- single use ----------------------------------------------------------------


def test_spend_elevated_grant_drops_a_single_use_grant_directly():
    """Hazard 5's mechanism, tested generically now that no live class is single-use
    (`provider:credentials` was, and is removed — ADR-0018 §6). `record_elevated_grant`
    can only mint through `ELEVATED_GRANT_SPECS`, which has no `single_use=True` member
    left to mint through, so this constructs the stored shape directly — the same way
    `test_a_malformed_stored_elevation_reads_as_none` does — to prove `spend_elevated_grant`
    still drops a single-use grant on its own terms, independent of which class sets the
    flag. If a future class sets `single_use=True` again, this is the test that would
    already have caught `spend` silently ceasing to honour it."""
    sess = _acting()
    sess["elevated_grant"] = {
        "id": "g-su",
        "tenant": TENANT,
        "provider_scope": SCOPE_PROVIDER_INVOKE,
        "gateway_scopes": ["tools:call"],
        "justification": WHY,
        "granted_at": 1000.0,
        "expires_at": 1000.0 + 900,
        "single_use": True,
        "access_token": STEP_UP_TOKEN,
    }
    assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) is not None
    spend_elevated_grant(sess)
    assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) is None


def test_an_invoke_elevation_survives_being_used():
    """The converse, and the reason `spend` cannot simply always drop. §8's grant gates
    *initiation*, not completion: one debugging session is several calls inside one window."""
    sess = _acting()
    _record(sess)
    spend_elevated_grant(sess)
    assert active_elevated_grant(sess, tenant=TENANT, now=1000.0) is not None


# --- through the app -----------------------------------------------------------


def _console_env(monkeypatch, tmp_path, **over) -> None:
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", PROVIDER_ISS)
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", TENANT)
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.setenv("PROVIDER_STEP_UP_ACR", over.get("acr", STEP_UP_ACR))
    monkeypatch.setenv(
        "PROVIDER_STEP_UP_REDIRECT_URL",
        over.get("redirect", "https://console.example.com/auth/provider/step-up/callback"),
    )
    # §11c: the scopes that tell the IdP which grant to mint. Factored as one scope per
    # tenant plus one per class, which is the shape that scales.
    monkeypatch.setenv(
        "PROVIDER_STEP_UP_SCOPE_TEMPLATE",
        over.get("scope_template", "mcp:tenant:{tenant} mcp:grant:{grant_class}"),
    )


class _FakeIdP:
    """A provider IdP that records what was asked of it and can decline the step-up.

    `declines_step_up` is the whole point of a fake here: a real IdP that always complies
    cannot exercise §11b's constraint 2, which is precisely the check most likely to be
    written as "we asked for it, so it happened".
    """

    def __init__(self, *, declines_step_up=False, acr=STEP_UP_ACR, claim=None, auth_time=None):
        self.declines_step_up = declines_step_up
        self.acr = acr
        self.claim = claim
        self.auth_time = auth_time
        self.asked = {}

    async def authorization_url(
        self, *, state, nonce, challenge, acr_values=None, max_age=None, redirect_uri=None, extra_scopes=None
    ):
        self.asked = {
            "state": state,
            "acr_values": acr_values,
            "max_age": max_age,
            "redirect_uri": redirect_uri,
            # §11c: what the request actually told the IdP to mint. Recorded because the
            # gap this closes was invisible for exactly as long as nothing looked at it —
            # the double answered with a hardcoded tenant no matter what it was asked.
            "extra_scopes": tuple(extra_scopes or ()),
        }
        return f"https://provider-idp.example.com/authorize?state={state}"

    async def exchange_code(self, *, code, verifier, redirect_uri=None):
        self.asked["exchange_redirect_uri"] = redirect_uri
        return {"id_token": "id.tok.sig", "access_token": STEP_UP_TOKEN}

    async def validate_id_token(self, *, id_token, nonce, access_token=None):
        import time as _t

        claims = {
            "sub": "u-provider-1",
            "name": "Pat",
            "groups": ["provider-support"],
            "nonce": nonce,
            "auth_time": self.auth_time if self.auth_time is not None else _t.time() - 5,
            "mcp_grant": (
                self.claim
                if self.claim is not None
                else {
                    "id": "g-7f2",
                    "tenant": TENANT,
                    "scopes": ["tools:call"],
                }
            ),
        }
        if not self.declines_step_up:
            claims["acr"] = self.acr
        return claims


@pytest.fixture
def console_no_scope_template(monkeypatch, tmp_path):
    """A BFF configured for step-ups except for the §11c scope template."""
    _console_env(monkeypatch, tmp_path, scope_template="")
    app = create_app()
    with TestClient(app) as c:
        yield c, app


@pytest.fixture
def console(monkeypatch, tmp_path):
    _console_env(monkeypatch, tmp_path)
    app = create_app()
    with TestClient(app) as c:
        yield c, app


def _acting_live(**over) -> dict:
    """`_acting`, but on the wall clock.

    The unit tests above pin `now=1000.0` so deadlines are exact arithmetic. The app-level
    ones go through routes that read `time.time()`, so an act minted at 1000.0 is decades
    expired before the request arrives — a fixture that looks live and is not.
    """
    import time as _t

    sess = _provider_session(**over)
    authorize_act_on_tenant(sess, tenant=TENANT, justification="ticket INC-4471", now=_t.time())
    return sess


def _seed_session(client, app, data: dict) -> None:
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200
    live = app.state.sessions._data
    assert len(live) == 1
    sid = next(iter(live))
    expires, _ = live[sid]
    live[sid] = (expires, dict(data))


def _stored(app) -> dict:
    return next(iter(app.state.sessions._data.values()))[1]


def _audited(app, action: str) -> list[dict]:
    rows = app.state.audit.read(tenant=TENANT, limit=200)
    return [r["content"] for r in reversed(rows) if r["content"] and r["content"]["action"] == action]


def _elevate(client, app, idp, *, scope=SCOPE_PROVIDER_INVOKE, justification=WHY):
    """Drive a full elevation: request → IdP → callback."""
    app.state.provider_oidc = idp
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": scope, "justification": justification},
        follow_redirects=False,
    )
    if resp.status_code >= 400:
        return resp
    state = resp.json()["authorization_url"].split("state=")[1]
    return client.get(f"/auth/provider/step-up/callback?code=abc&state={state}", follow_redirects=False)


def test_the_step_up_request_asks_for_the_configured_acr(console):
    """It must actually be requested — which is necessary and, on its own, worthless. The
    test that it is *verified* is the next one, and this exists so that one cannot pass
    vacuously against an IdP that was never asked."""
    client, app = console
    _seed_session(client, app, _acting_live())
    idp = _FakeIdP()
    _elevate(client, app, idp)
    assert idp.asked["acr_values"] == STEP_UP_ACR
    assert idp.asked["max_age"] == 0


# --- §11c: the request has to say WHICH grant to mint --------------------------
#
# §11b assumed the IdP could mint a grant from a request naming neither the tenant nor the
# class. Measurement against two real IdPs killed that: nothing survives to issuance except
# the requested scopes. The gap was invisible here for as long as this file's double
# answered with a hardcoded tenant no matter what it was asked — so these tests assert on
# what the IdP was *told*, which is the only thing a double cannot fake on our behalf.


def test_the_step_up_request_names_the_tenant_and_the_class(console):
    """Without this the IdP is being asked to guess, and a real one returns no claim."""
    client, app = console
    _seed_session(client, app, _acting_live())
    idp = _FakeIdP()
    _elevate(client, app, idp)
    assert idp.asked["extra_scopes"] == ("mcp:tenant:acme", "mcp:grant:invoke")


# The sibling test to the one above used to elevate `provider:credentials` and assert the
# request named *that* class rather than `provider:invoke`'s — proving the scope follows
# whichever class is asked for, not a fixed one. With `provider:credentials` removed
# (ADR-0018 §6) there is only one class left to ask for, so that comparison has no second
# case to make it meaningful. `step_up_scopes`'s own parametrized tests below
# (`test_the_template_expresses_either_factoring` et al.) already cover the substitution
# generically at the unit level; nothing here would newly regress by this test's absence.


def test_a_bff_with_no_scope_template_refuses_before_the_round_trip(console_no_scope_template):
    """Fail closed, and fail *early*. A step-up that cannot name its grant comes back
    without one, so the alternative is walking an operator through a second factor to
    reach a refusal that was knowable before the redirect was built."""
    client, app = console_no_scope_template
    _seed_session(client, app, _acting_live())
    idp = _FakeIdP()
    app.state.provider_oidc = idp
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    assert resp.status_code == 400
    assert "scope template" in resp.json()["detail"]
    # ...and the IdP was never asked, which is the point of failing early.
    assert idp.asked == {}


def test_the_step_up_scopes_are_added_to_the_configured_ones_not_substituted():
    """Replacing rather than appending would drop `openid`, and with it the id_token this
    flow verifies — a step-up that silently stops being verifiable."""
    from app.oidc import OIDCClient

    class _S:
        oidc_issuer = "https://idp.example.com"
        oidc_client_id = "cid"
        oidc_client_secret = ""
        oidc_redirect_url = "https://console.example.com/cb"
        oidc_scopes = "openid profile email"

    client = OIDCClient(_S())
    client._meta = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
    }
    url = asyncio.run(
        client.authorization_url(state="s", nonce="n", challenge="c", extra_scopes=("mcp:tenant:acme", "openid"))
    )
    scope = parse_qs(urlparse(url).query)["scope"][0].split()
    assert "openid" in scope and "profile" in scope
    assert "mcp:tenant:acme" in scope
    assert scope.count("openid") == 1, "a scope already requested must not be repeated"


@pytest.mark.parametrize(
    "template, expected",
    [
        ("mcp:tenant:{tenant} mcp:grant:{grant_class}", ("mcp:tenant:acme", "mcp:grant:invoke")),
        ("mcp:grant:{tenant}:{grant_class}", ("mcp:grant:acme:invoke",)),
        ("  spaced:{tenant}   ", ("spaced:acme",)),
    ],
)
def test_the_template_expresses_either_factoring(template, expected):
    """One scope per tenant plus one per class, or one combined scope. The deployment
    decides; scope names are registered in someone else's IdP."""
    assert step_up_scopes(template, tenant=TENANT, provider_scope=SCOPE_PROVIDER_INVOKE) == expected


def test_an_unconfigured_template_says_the_deployment_is_not_set_up():
    """The unset case gets its own message, and it needs asserting: a blank template also
    renders to nothing, so the later "rendered to nothing" guard catches it too. With a
    loose assertion the explicit early check could be deleted and nothing would notice —
    which is what mutation testing showed. Its value is the diagnosis it gives an operator,
    so the diagnosis is what the test pins."""
    with pytest.raises(GrantError, match="which grant to mint"):
        step_up_scopes("", tenant=TENANT, provider_scope=SCOPE_PROVIDER_INVOKE)


def test_a_template_of_only_whitespace_is_refused_as_rendering_nothing():
    """A different fault — a configured template that produces no scopes — and so a
    different message. Settings strip the env var, so this arrives only from a caller."""
    with pytest.raises(GrantError, match="rendered to nothing"):
        step_up_scopes("   ", tenant=TENANT, provider_scope=SCOPE_PROVIDER_INVOKE)


def test_a_template_naming_an_unknown_placeholder_is_refused():
    """Better a refusal naming the placeholder than a KeyError escaping as a 500."""
    with pytest.raises(GrantError, match="only"):
        step_up_scopes("mcp:{whatever}", tenant=TENANT, provider_scope=SCOPE_PROVIDER_INVOKE)


@pytest.mark.parametrize("bad_tenant", ["a b", "acme other", "", "../etc", "x" * 200])
def test_a_tenant_that_could_inject_a_second_scope_is_refused(bad_tenant):
    """Scopes are space-delimited, so a tenant carrying whitespace would append a scope of
    the caller's choosing to the authorization request. Re-checked here rather than relied
    on from the caller, because this is the code whose correctness depends on it."""
    with pytest.raises(GrantError):
        step_up_scopes("mcp:tenant:{tenant}", tenant=bad_tenant, provider_scope=SCOPE_PROVIDER_INVOKE)


def test_a_non_elevated_provider_scope_has_no_class_name():
    """`provider:admin` is an everyday scope, not a grant class — there is no step-up to
    request for it, and no class name to interpolate."""
    with pytest.raises(GrantError, match="not an elevated grant class"):
        step_up_scopes("mcp:grant:{grant_class}", tenant=TENANT, provider_scope="provider:admin")


def test_an_idp_that_declines_the_step_up_gets_no_elevation(console):
    """Hazard 1, and §11b constraint 2 — the single most important test in this file.

    `acr_values` is a request parameter. This IdP issues a perfectly valid token, with a
    valid grant claim, having simply not performed the step-up. Every signature verifies.
    An implementation that checks it *asked* rather than what it *got* passes everything
    else here and fails only in production, silently.
    """
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _elevate(client, app, _FakeIdP(declines_step_up=True))
    assert resp.status_code == 403, resp.text
    assert _stored(app).get("elevated_grant") is None
    denied = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "denied"]
    assert denied and "acr" in denied[-1]["detail"]["reason"]


def test_a_different_acr_than_the_configured_one_is_refused(console):
    """A step-up to some *other* context is not this context. Refusing anything but the
    configured value is what stops "the IdP did something extra" being read as "the IdP did
    the thing we require"."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _elevate(client, app, _FakeIdP(acr="urn:some:other:context"))
    assert resp.status_code == 403
    assert _stored(app).get("elevated_grant") is None


def test_a_successful_elevation_is_audited_with_its_justification(console):
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _elevate(client, app, _FakeIdP())
    assert resp.status_code in (200, 302), resp.text

    records = _audited(app, "provider.elevate")
    ok = [r for r in records if r["outcome"] == "success"]
    assert len(ok) == 1
    assert ok[0]["target"] == TENANT
    assert ok[0]["detail"]["justification"] == WHY
    assert ok[0]["detail"]["scope"] == SCOPE_PROVIDER_INVOKE
    assert ok[0]["detail"]["grant"] == "g-7f2"


def test_the_step_up_token_is_relayed_upstream_while_the_elevation_is_live(console):
    """What the whole slice is for: the token carrying `mcp_grant` reaches the gateway,
    which is what raises the ceiling on that side (MCP-Gateway #119).

    Driven through the tool-invocation route rather than an ordinary read. The elevated
    credential is handed only to routes that declared they need it — a read would (and now
    does) get the ordinary token, because the gateway consumes a grant on first validation
    and a routine request must not be what spends it. See `test_elevated_routes.py`.
    """
    client, app = console
    _seed_session(client, app, _acting_live())
    _elevate(client, app, _FakeIdP())

    seen = []

    async def _spy(method, path, json=None, bearer=None, headers=None):
        import httpx

        seen.append(bearer)
        hdrs = {"Mcp-Session-Id": "s-1"} if (json or {}).get("method") == "initialize" else {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}}, headers=hdrs)

    app.state.gateway.request = _spy
    assert client.post("/api/devices/dev1/tools/probe/invoke", json={"arguments": {}}).status_code == 200
    assert seen and set(seen) == {STEP_UP_TOKEN}


def test_an_elevation_with_no_act_underneath_it_is_not_relayed(console):
    """An elevation is authority *within* an act. A session carrying one with no act — a
    crafted session, or one whose act was removed out from under it in a shared store —
    must fall back to the ordinary token, not present the elevated one.

    Reachable only by constructing the state directly, which is the point: every other path
    keeps the two in step, so nothing else here would notice if the relay stopped checking.
    """
    import time as _t

    client, app = console
    now = _t.time()
    sess = _acting_live()
    _record(sess, now=now, claim=_claim(exp=now + 900))
    sess.pop("act_on_tenant")
    _seed_session(client, app, sess)

    seen = {}

    async def _spy(path, bearer=None, **kw):
        import httpx

        seen["bearer"] = bearer
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _spy
    resp = client.get("/api/devices")
    # Refused at the gate for want of an act — and, whatever the status, the elevated token
    # must not have gone anywhere.
    assert resp.status_code == 403
    assert seen.get("bearer") != STEP_UP_TOKEN


async def test_upstream_bearer_will_not_present_an_elevation_with_no_act():
    """The same rule at its own level, because the route-level test above cannot reach it.

    `require_role` refuses a provider session with no act, so the request never gets as far
    as choosing a credential — meaning that test passes whether or not `upstream_bearer`
    checks. Two layers of defence, and the outer one hides the inner: exactly the shape
    that let the admin-key fallback survive earlier in this slice. Called directly.
    """
    import time as _t

    from app.security import upstream_bearer

    class _Req:
        def __init__(self, sess):
            # `elevated_scope` is what a route's `require_elevated` dependency sets, and
            # without it `upstream_bearer` hands over the ordinary token by design. Set here
            # so this test exercises the act check rather than passing because the credential
            # was never going to be offered in the first place.
            self.state = SimpleNamespace(_bff_session=sess, elevated_scope=SCOPE_PROVIDER_INVOKE)

    now = _t.time()
    sess = _acting_live()
    # A live claim expiry: `_claim()`'s default is pinned to the 1000.0 unit-test clock, and
    # the cap would pull this grant's deadline decades into the past.
    _record(sess, now=now, claim=_claim(exp=now + 900))
    assert await upstream_bearer(_Req(sess)) == STEP_UP_TOKEN  # the control

    sess.pop("act_on_tenant")
    assert await upstream_bearer(_Req(sess)) == OPERATOR_TOKEN


def test_without_an_elevation_the_ordinary_operator_token_is_relayed(console):
    """The control. Without it, the test above would pass on an implementation that always
    presents whatever token it saw last."""
    client, app = console
    _seed_session(client, app, _acting_live())

    seen = {}

    async def _spy(path, bearer=None, **kw):
        import httpx

        seen["bearer"] = bearer
        return httpx.Response(200, json={"devices": []})

    app.state.gateway.get = _spy
    assert client.get("/api/devices").status_code == 200
    assert seen["bearer"] == OPERATOR_TOKEN


def test_elevating_without_an_act_on_that_tenant_is_refused_by_the_route(console):
    client, app = console
    _seed_session(client, app, _provider_session())
    resp = _elevate(client, app, _FakeIdP())
    assert resp.status_code == 400
    assert _stored(app).get("elevated_grant") is None


def test_a_tenant_session_cannot_request_an_elevation(console):
    client, app = console
    _seed_session(client, app, {"kind": "password", "role": "admin", "plane": PLANE_TENANT})
    resp = _elevate(client, app, _FakeIdP())
    assert resp.status_code == 403


def test_a_monitor_only_session_cannot_request_an_elevation(console):
    """§7: `provider:monitor` holds no tenant API access at all, so it must not be able to
    elevate — and the act is seeded *before* the scopes are narrowed, because a monitor
    session cannot mint an act either. Building the session the other way round would have
    the act check refuse first and this test would pass without exercising the scope gate.
    """
    client, app = console
    sess = _acting_live()
    sess["provider_scopes"] = [SCOPE_PROVIDER_MONITOR]
    _seed_session(client, app, sess)
    resp = _elevate(client, app, _FakeIdP())
    assert resp.status_code == 403


def test_a_justification_is_required_for_an_elevation_too(console):
    """§8 puts elevated grants *above* act-on-tenant, so the everyday act cannot be the
    only one that has to say why."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _elevate(client, app, _FakeIdP(), justification="   ")
    assert resp.status_code == 400
    assert _stored(app).get("elevated_grant") is None


def test_a_step_up_callback_cannot_be_replayed_into_a_different_transaction(console):
    """The transaction is single-use and bound: the callback pops it. Replaying the same
    state must not mint a second elevation — which would turn one step-up into as many
    grants as an attacker can replay the redirect."""
    client, app = console
    _seed_session(client, app, _acting_live())
    idp = _FakeIdP()
    app.state.provider_oidc = idp
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    state = resp.json()["authorization_url"].split("state=")[1]
    first = client.get(f"/auth/provider/step-up/callback?code=abc&state={state}", follow_redirects=False)
    assert first.status_code in (200, 302)
    second = client.get(f"/auth/provider/step-up/callback?code=abc&state={state}", follow_redirects=False)
    assert second.status_code >= 400


def test_a_live_transaction_with_a_mismatched_state_is_refused(console):
    """The state comparison, exercised with a transaction actually present.

    The replay test above pops the transaction, and the forged-state test below has none at
    all — so both are refused by the "no transaction" branch and neither touches the
    comparison. This is the case where a transaction *is* in flight and the callback
    carries someone else's state, which is the shape a forged callback actually has.
    """
    client, app = console
    _seed_session(client, app, _acting_live())
    app.state.provider_oidc = _FakeIdP()
    client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    resp = client.get("/auth/provider/step-up/callback?code=abc&state=someone-elses", follow_redirects=False)
    assert resp.status_code == 400
    assert _stored(app).get("elevated_grant") is None


def test_the_callback_cannot_re_aim_the_elevation_at_another_tenant(console):
    """The reason the tenant rides in the server-side transaction rather than the URL.

    A callback is a URL an attacker can influence. If the tenant were read from it, one
    step-up authorised for `acme` could be redirected into a grant over `globex` — and the
    audit record would name the tenant the attacker chose. The query parameter must be
    inert.
    """
    client, app = console
    _seed_session(client, app, _acting_live())
    idp = _FakeIdP()
    app.state.provider_oidc = idp
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    state = resp.json()["authorization_url"].split("state=")[1]
    resp = client.get(
        f"/auth/provider/step-up/callback?code=abc&state={state}&tenant=globex",
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302), resp.text
    assert _stored(app)["elevated_grant"]["tenant"] == TENANT
    ok = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "success"]
    assert ok[-1]["target"] == TENANT


def test_a_forged_state_is_refused_and_recorded(console):
    """A forged callback is an attack signal, not a user error."""
    client, app = console
    _seed_session(client, app, _acting_live())
    app.state.provider_oidc = _FakeIdP()
    resp = client.get("/auth/provider/step-up/callback?code=abc&state=not-the-state", follow_redirects=False)
    assert resp.status_code >= 400
    denied = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "denied"]
    assert denied


def test_step_up_is_off_unless_configured(monkeypatch, tmp_path):
    """The *default*, with the variable absent rather than explicitly emptied.

    Setting it to "" tests that an empty value disables the feature; it says nothing about
    what happens when an operator has never heard of it. A default that quietly enabled a
    step-up against an `acr` nobody configured would pass that test and fail here.
    """
    _console_env(monkeypatch, tmp_path)
    monkeypatch.delenv("PROVIDER_STEP_UP_ACR", raising=False)
    app = create_app()
    assert app.state.settings.provider_step_up_acr == ""
    with TestClient(app) as client:
        _seed_session(client, app, _acting_live())
        assert _elevate(client, app, _FakeIdP()).status_code == 404


def test_step_up_is_unavailable_when_no_acr_is_configured(monkeypatch, tmp_path):
    """Fail closed on config. Without a step-up context there is nothing to verify, so the
    elevated grants are simply not offered — rather than offered and unverifiable, which is
    the state §11b's constraint exists to prevent."""
    _console_env(monkeypatch, tmp_path)
    monkeypatch.setenv("PROVIDER_STEP_UP_ACR", "")
    app = create_app()
    with TestClient(app) as client:
        _seed_session(client, app, _acting_live())
        resp = _elevate(client, app, _FakeIdP())
        assert resp.status_code == 404
        assert _stored(app).get("elevated_grant") is None


def test_releasing_the_act_drops_the_elevation_through_the_route(console):
    client, app = console
    _seed_session(client, app, _acting_live())
    _elevate(client, app, _FakeIdP())
    assert _stored(app).get("elevated_grant") is not None

    client.delete("/provider/act-on-tenant")
    assert _stored(app).get("elevated_grant") is None


# The end-to-end "spent by one relayed request" test lived here, against
# `provider:credentials` and `/api/admin/backup`. Both are gone: the class is removed
# (ADR-0018 §6) and the route no longer requires any elevation (it now needs only an
# ordinary admin session — `_admin`, not `_needs_credentials`). No live route is single-use
# today, so there is nothing to drive this end to end against.
# `test_spend_elevated_grant_drops_a_single_use_grant_directly` (above) covers the same
# hazard at the unit level in the meantime; restore an end-to-end version of this test
# alongside whichever future route first needs `single_use=True` for real.


def test_the_elevated_token_never_reaches_the_browser(console):
    """It is the most valuable thing this BFF holds — a bearer that raises a customer
    gateway's ceiling. The browser gets the grant's shape and nothing else."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _elevate(client, app, _FakeIdP())
    assert STEP_UP_TOKEN not in resp.text
    body = client.get("/provider/act-on-tenant").text
    assert STEP_UP_TOKEN not in body
    assert WHY not in body


def test_the_step_up_uses_its_own_transaction_key(console):
    """Separate from the login transaction, so a step-up in flight cannot be completed by
    a login callback or the reverse — the same reason the two login routes are structurally
    separate rather than one route with a `plane=` selector."""
    client, app = console
    _seed_session(client, app, _acting_live())
    app.state.provider_oidc = _FakeIdP()
    client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    cookie_session = client.cookies
    assert cookie_session is not None  # the tx lives in the signed cookie session
    # A *login* callback must not be able to consume the step-up transaction.
    resp = client.get("/auth/provider/callback?code=abc&state=whatever", follow_redirects=False)
    assert resp.status_code >= 400
    assert _stored(app).get("elevated_grant") is None


# --- what the console reads (the browser half of §4/§8) -----------------------
#
# The mechanism above was API-only until the console existed. These cover the three
# surfaces a browser needs and nothing else did: a *read* of the live elevation, the
# deployment's own answer to "which console am I", and the fact that a step-up returns by
# **navigation** — so its outcome has to arrive somewhere a browser can act on.


def test_the_console_can_read_the_live_elevation(console):
    """Without a read there is no countdown, and no way to show single-use as a state."""
    client, app = console
    _seed_session(client, app, _acting_live())
    _elevate(client, app, _FakeIdP())

    body = client.get("/provider/elevation").json()
    assert body["tenant"] == TENANT
    assert body["scope"] == SCOPE_PROVIDER_INVOKE
    assert body["single_use"] is False
    assert body["expires_at"] > body["granted_at"]


def test_the_read_route_renders_single_use_true_when_the_stored_grant_says_so(console):
    """The other half of the field above. No live class sets `single_use=True` today
    (`provider:credentials` did, and is removed — ADR-0018 §6), so this seeds the stored
    shape directly rather than through a real elevation, the same way
    `test_spend_elevated_grant_drops_a_single_use_grant_directly` does — proving the read
    route still renders the field correctly for whenever a class needs it again."""
    client, app = console
    sess = _acting_live()
    import time as _t

    now = _t.time()
    sess["elevated_grant"] = {
        "id": "g-su",
        "tenant": TENANT,
        "provider_scope": SCOPE_PROVIDER_INVOKE,
        "gateway_scopes": ["tools:call"],
        "justification": WHY,
        "granted_at": now,
        "expires_at": now + 900,
        "single_use": True,
        "access_token": STEP_UP_TOKEN,
    }
    _seed_session(client, app, sess)

    body = client.get("/provider/elevation").json()
    assert body["single_use"] is True


def test_reading_the_elevation_never_hands_back_the_token_or_the_justification(console):
    """The step-up token is the most valuable thing this BFF holds. A read route added for a
    countdown is exactly where it would leak by being copied from `as_dict()`."""
    client, app = console
    _seed_session(client, app, _acting_live())
    _elevate(client, app, _FakeIdP())

    body = client.get("/provider/elevation").json()
    assert "access_token" not in body
    assert "justification" not in body
    # And the value is genuinely held — otherwise the assertions above pass vacuously.
    assert _stored(app)["elevated_grant"]["access_token"]


def test_no_act_means_no_elevation_is_reported(console):
    """An elevation is authority over one tenant. With no live act there is no tenant being
    acted on, so there is nothing to report — even though the session still holds the
    record. Reporting it would show the operator an elevation no route would honour."""
    client, app = console
    _seed_session(client, app, _acting_live())
    _elevate(client, app, _FakeIdP())
    assert client.get("/provider/elevation").json()["tenant"] == TENANT

    client.delete("/provider/act-on-tenant")
    assert client.get("/provider/elevation").json() == {"elevation": None}


def test_reading_the_elevation_does_not_spend_or_renew_it(console):
    """A console polls this once a second. If the read consumed or extended anything, the
    countdown would be the thing destroying what it displays."""
    client, app = console
    _seed_session(client, app, _acting_live())
    _elevate(client, app, _FakeIdP())

    first = client.get("/provider/elevation").json()
    for _ in range(3):
        again = client.get("/provider/elevation").json()
    assert again == first  # same id, same deadline — no spend, no extension
    assert _stored(app).get("elevated_grant") is not None


def test_a_tenant_session_cannot_read_the_elevation(console):
    """The plane wall, on the route added last. Every provider route is checked in both
    directions; a read route is the easy one to add outside the gate."""
    client, app = console
    resp = client.post("/auth/login", json={"password": "admin-pw"})  # password ⇒ tenant plane
    assert resp.status_code == 200
    assert client.get("/provider/elevation").status_code == 403


def test_the_config_tells_the_spa_which_console_this_is(console):
    """The SPA renders the provider login from this and nothing else. It is not a selector:
    `create_app` refuses to start with both IdPs, so these two are mutually exclusive."""
    client, _ = console
    body = client.get("/auth/config").json()
    assert body["provider_enabled"] is True
    assert body["oidc_enabled"] is False
    assert body["step_up_enabled"] is True


def test_step_up_is_reported_unavailable_when_it_cannot_be_verified(monkeypatch, tmp_path):
    """A provider console with no `acr` configured is correctly configured and simply does
    not offer elevated grants. The console must be able to hide the affordance rather than
    find out by clicking it and collecting a 404."""
    _console_env(monkeypatch, tmp_path, acr="")
    app = create_app()
    with TestClient(app) as client:
        body = client.get("/auth/config").json()
        assert body["provider_enabled"] is True
        assert body["step_up_enabled"] is False


# --- the callback is reached by navigation ------------------------------------


def _browser_elevate(client, app, idp, *, scope=SCOPE_PROVIDER_INVOKE):
    """`_elevate`, but with the callback fetched the way a browser fetches it."""
    app.state.provider_oidc = idp
    resp = client.post(f"/provider/tenants/{TENANT}/elevate", json={"scope": scope, "justification": WHY})
    state = resp.json()["authorization_url"].split("state=")[1]
    return client.get(
        f"/auth/provider/step-up/callback?code=abc&state={state}",
        headers={"accept": "text/html,application/xhtml+xml"},
        follow_redirects=False,
    )


def test_a_browser_step_up_lands_back_in_the_console(console):
    """The IdP sends the operator's *browser* here. A JSON body is not an outcome a browser
    can act on — the operator would be looking at raw text where the console should be."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _browser_elevate(client, app, _FakeIdP())
    assert resp.status_code == 302
    assert "elevation=granted" in resp.headers["location"]
    # And the grant is real, not merely announced.
    assert _stored(app)["elevated_grant"]["tenant"] == TENANT


def test_a_declined_step_up_lands_back_saying_so(console):
    """§11b constraint 2 through the browser. This is the case a real IdP produces — a
    perfectly valid token with no step-up performed — so it has to arrive as a stated
    outcome the console can name, not as an error page."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _browser_elevate(client, app, _FakeIdP(declines_step_up=True))
    assert resp.status_code == 302
    assert "elevation=denied" in resp.headers["location"]
    assert "reason=step_up_declined" in resp.headers["location"]
    # Refused, and refused *before* anything was stored.
    assert _stored(app).get("elevated_grant") is None
    denied = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "denied"]
    assert denied and "acr" in denied[-1]["detail"]["reason"]


def test_the_landing_never_carries_the_refusal_text(console):
    """The outcome travels in a URL, and a URL is logged by every proxy on the way. The
    exception's own text names the tenant and quotes the configured `acr`; the closed
    vocabulary is what keeps that in the audit record and out of access logs."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _browser_elevate(client, app, _FakeIdP(declines_step_up=True))
    location = resp.headers["location"]
    assert STEP_UP_ACR not in location
    assert TENANT not in location


def test_an_api_client_still_gets_the_status_code_it_checks_for(console):
    """The browser affordance must not soften a refusal for a caller that was checking for
    one. Same declined step-up, a client that did not ask for HTML: still a 403."""
    client, app = console
    _seed_session(client, app, _acting_live())
    resp = _elevate(client, app, _FakeIdP(declines_step_up=True))
    assert resp.status_code == 403


def test_an_idp_refusal_is_not_reported_as_a_broken_callback(console):
    """Found in a browser, not here: an unattached client scope made Keycloak refuse with
    `error=invalid_scope`, and the console said "the step-up came back incomplete" — true of
    nothing that happened, and it points the reader at the transport instead of at the
    directory config that was actually wrong.

    The two failures share a shape and nothing else. One is unactionable; the other names a
    deployment fault someone can go and fix.
    """
    client, app = console
    _seed_session(client, app, _acting_live())
    app.state.provider_oidc = _FakeIdP()
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    state = resp.json()["authorization_url"].split("state=")[1]

    cb = client.get(
        f"/auth/provider/step-up/callback?error=invalid_scope&state={state}",
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert cb.status_code == 302
    assert "reason=idp_refused" in cb.headers["location"]
    assert "invalid_callback" not in cb.headers["location"]

    denied = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "denied"]
    # The IdP's own code is what makes the record actionable.
    assert denied[-1]["detail"]["reason"] == "idp_refused"
    assert denied[-1]["detail"]["idp_error"] == "invalid_scope"
    assert _stored(app).get("elevated_grant") is None


def test_the_idp_error_text_is_bounded_before_it_enters_the_chain(console):
    """`error` is unbounded input from another system landing in an append-only record that
    nothing can later edit. The code is what identifies the fault; the essay is not."""
    client, app = console
    _seed_session(client, app, _acting_live())
    app.state.provider_oidc = _FakeIdP()
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    state = resp.json()["authorization_url"].split("state=")[1]
    client.get(f"/auth/provider/step-up/callback?error={'x' * 500}&state={state}", follow_redirects=False)

    denied = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "denied"]
    assert len(denied[-1]["detail"]["idp_error"]) <= 64


def test_a_truncated_callback_is_still_reported_as_one(console):
    """The other half of the split. Without this, "distinguish them" could be satisfied by
    relabelling *everything* as an IdP refusal, which is the same defect facing the other way."""
    client, app = console
    _seed_session(client, app, _acting_live())
    app.state.provider_oidc = _FakeIdP()
    resp = client.post(
        f"/provider/tenants/{TENANT}/elevate",
        json={"scope": SCOPE_PROVIDER_INVOKE, "justification": WHY},
    )
    state = resp.json()["authorization_url"].split("state=")[1]

    # No `code`, and no `error` either — the redirect simply arrived incomplete.
    cb = client.get(
        f"/auth/provider/step-up/callback?state={state}",
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert "reason=invalid_callback" in cb.headers["location"]
    denied = [r for r in _audited(app, "provider.elevate") if r["outcome"] == "denied"]
    assert denied[-1]["detail"]["reason"] == "invalid_callback"
    assert "idp_error" not in denied[-1]["detail"]


# --- signing out of the provider console (found in a browser) ------------------


class _LogoutIdP(_FakeIdP):
    """A provider RP that exposes RP-initiated logout, which `_FakeIdP` does not."""

    async def end_session_url(self, *, id_token_hint, post_logout_redirect_uri=None):
        return f"https://provider-idp.example/logout?id_token_hint={id_token_hint}"


def test_signing_out_of_the_provider_console_ends_the_idp_session_too(console):
    """The defect: `logout` read `state.oidc` — the *tenant* RP — which is `None` on a
    provider console by construction (§2/§5). So no logout URL was ever returned, the
    provider IdP's cookie survived, and the next "Sign in with the provider directory" was
    **silent SSO with no prompt** — handing the next person at that browser cross-tenant
    authority behind a sign-out that looked like it worked.

    Every existing logout test passed the whole time. They only drove the tenant plane, and
    the one line that chose the RP was the one thing they could not see.
    """
    client, app = console
    app.state.provider_oidc = _LogoutIdP()
    _seed_session(client, app, {**_provider_session(), "kind": "oidc", "id_token": "prov.id.tok"})

    body = client.post("/auth/logout").json()
    assert body["end_session_url"], "a provider session must be able to end its IdP session"
    assert "prov.id.tok" in body["end_session_url"]


def test_the_tenant_plane_still_logs_out_against_the_tenant_rp(console):
    """The other half. Selecting by plane must not send a tenant session to the provider
    IdP — that would be the same defect pointing the other way, and it would leak which
    provider IdP a tenant stack is adjacent to."""
    client, app = console
    app.state.provider_oidc = _LogoutIdP()
    app.state.oidc = None  # a provider console has no tenant RP
    client.post("/auth/login", json={"password": "admin-pw"})  # password ⇒ tenant plane

    body = client.post("/auth/logout").json()
    assert body["end_session_url"] is None
