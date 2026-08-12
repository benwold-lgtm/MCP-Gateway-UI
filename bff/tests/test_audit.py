# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""BFF audit chain: tamper-evidence, per-tenant content keys, actor pseudonymization.

The tests that matter here are the ones asserting a *negative*: that an altered record
is detected, that a shredded tenant's records still verify, and that a provider actor's
real subject never reaches the file. Each of those is a property the design claims and
which nothing else in the suite would notice breaking.
"""

import json

from cryptography.fernet import Fernet

from app.audit import (
    ACTOR_PROVIDER,
    ACTOR_TENANT,
    ENC_FERNET,
    OUTCOME_SUCCESS,
    AuditLog,
    Pseudonymizer,
    TenantKeyring,
    actor_from_session,
    outcome_for,
    verify_chain,
)


def _log(tmp_path, *, tenant="acme", key=True, pseudonym_key=b"pseudo-key", instance="i-1"):
    keyring = TenantKeyring()
    if key:
        keyring.add(tenant, Fernet.generate_key())
    return AuditLog(
        path=tmp_path / "audit.log",
        tenant=tenant,
        keyring=keyring,
        pseudonymizer=Pseudonymizer(pseudonym_key),
        instance_id=instance,
        echo=False,
    )


def _lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --- chain integrity --------------------------------------------------------


def test_chain_links_and_verifies(tmp_path):
    log = _log(tmp_path)
    for i in range(5):
        log.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target=f"dev{i}")

    ok, detail = verify_chain(tmp_path / "audit.log")
    assert ok, detail

    recs = _lines(tmp_path / "audit.log")
    assert [r["seq"] for r in recs] == [0, 1, 2, 3, 4]
    assert recs[0]["prev"] == "0" * 64
    # Each record's prev is its predecessor's hash — that is what makes deletion visible.
    for earlier, later in zip(recs, recs[1:]):
        assert later["prev"] == earlier["hash"]


def test_an_altered_record_is_detected(tmp_path):
    log = _log(tmp_path)
    log.record("device.delete", actor="alice", outcome=OUTCOME_SUCCESS, target="dev0")
    log.record("device.delete", actor="alice", outcome=OUTCOME_SUCCESS, target="dev1")

    path = tmp_path / "audit.log"
    recs = _lines(path)
    recs[0]["ts"] = "2000-01-01T00:00:00+00:00"  # backdate one record
    path.write_text("\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in recs) + "\n")

    ok, detail = verify_chain(path)
    assert not ok
    assert "altered" in detail


def test_a_deleted_record_is_detected(tmp_path):
    log = _log(tmp_path)
    for i in range(3):
        log.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target=f"dev{i}")

    path = tmp_path / "audit.log"
    recs = _lines(path)
    del recs[1]  # excise the middle record
    path.write_text("\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in recs) + "\n")

    ok, detail = verify_chain(path)
    assert not ok
    # The gap is caught on sequence before the broken link is reached; either is a pass.
    assert "gap" in detail or "deleted or reordered" in detail


def test_interleaved_replicas_are_not_mistaken_for_tampering(tmp_path):
    """Two BFF replicas appending to one sink each keep their own sub-chain."""
    a = _log(tmp_path, instance="replica-a")
    b = _log(tmp_path, instance="replica-b")
    b.keyring = a.keyring  # same tenant key; only the chain differs
    for i in range(3):
        a.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target=f"a{i}")
        b.record("device.update", actor="bob", outcome=OUTCOME_SUCCESS, target=f"b{i}")

    ok, detail = verify_chain(tmp_path / "audit.log")
    assert ok, detail
    assert "2 instance(s)" in detail


def test_a_restart_continues_the_chain_rather_than_resetting_it(tmp_path):
    first = _log(tmp_path)
    first.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target="dev0")
    first.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target="dev1")

    # A fresh process over the same file, same instance id: seq must continue, not restart.
    second = _log(tmp_path)
    second.keyring = first.keyring
    second.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target="dev2")

    recs = _lines(tmp_path / "audit.log")
    assert [r["seq"] for r in recs] == [0, 1, 2]
    ok, detail = verify_chain(tmp_path / "audit.log")
    assert ok, detail


# --- per-tenant content keys (ADR-0013 §10) ---------------------------------


def test_content_is_encrypted_and_the_plaintext_is_not_on_disk(tmp_path):
    log = _log(tmp_path)
    log.record("device.delete", actor="alice", outcome=OUTCOME_SUCCESS, target="secret-host")

    raw = (tmp_path / "audit.log").read_text()
    assert "secret-host" not in raw
    assert "alice" not in raw
    rec = _lines(tmp_path / "audit.log")[0]
    assert rec["enc"] == ENC_FERNET
    assert isinstance(rec["content"], str)

    # Readable while the key exists.
    opened = log.read()
    assert opened[0]["readable"] is True
    assert opened[0]["content"]["target"] == "secret-host"


def test_shredding_a_tenant_leaves_the_chain_verifiable(tmp_path):
    """The point of committing to ciphertext: erasure must not cost tamper-evidence."""
    log = _log(tmp_path)
    for i in range(3):
        log.record("device.update", actor="alice", outcome=OUTCOME_SUCCESS, target=f"dev{i}")

    assert log.keyring.shred("acme") is True

    ok, detail = verify_chain(tmp_path / "audit.log")
    assert ok, detail  # verification needs no key at all

    # The activity is still visibly present; its content is gone.
    rows = log.read()
    assert len(rows) == 3
    assert all(r["readable"] is False and r["content"] is None for r in rows)


def test_a_tenant_key_cannot_read_another_tenants_records(tmp_path):
    keyring = TenantKeyring()
    keyring.add("acme", Fernet.generate_key())
    keyring.add("globex", Fernet.generate_key())
    log = AuditLog(path=tmp_path / "audit.log", tenant="acme", keyring=keyring, echo=False, instance_id="i-1")

    log.record("device.delete", actor="alice", outcome=OUTCOME_SUCCESS, target="acme-host")
    log.record("device.delete", actor="bob", outcome=OUTCOME_SUCCESS, target="globex-host", tenant="globex")

    # Reading as acme returns only acme's row, and shredding acme leaves globex readable.
    assert [r["content"]["target"] for r in log.read(tenant="acme")] == ["acme-host"]
    keyring.shred("acme")
    assert log.read(tenant="acme")[0]["readable"] is False
    assert log.read(tenant="globex")[0]["content"]["target"] == "globex-host"


def test_without_a_key_content_is_plaintext_and_shredding_is_unavailable(tmp_path):
    """Supported, but it forfeits §10 — the test states that plainly rather than hiding it."""
    log = _log(tmp_path, key=False)
    log.record("device.delete", actor="alice", outcome=OUTCOME_SUCCESS, target="visible-host")

    rec = _lines(tmp_path / "audit.log")[0]
    assert rec["enc"] == "none"
    assert rec["content"]["target"] == "visible-host"
    assert log.keyring.shred("acme") is False  # nothing to destroy
    ok, _ = verify_chain(tmp_path / "audit.log")
    assert ok


# --- actor pseudonymization (ADR-0013 §9) -----------------------------------


def test_a_provider_actor_is_pseudonymized_before_the_bytes_are_written(tmp_path):
    log = _log(tmp_path)
    log.record("device.update", actor="engineer@provider.example", actor_kind=ACTOR_PROVIDER, outcome=OUTCOME_SUCCESS)

    # Not in the file even as ciphertext input — check the decrypted view too, because
    # the tenant is entitled to read this and must still not learn the real identity.
    assert "engineer@provider.example" not in (tmp_path / "audit.log").read_text()
    content = log.read()[0]["content"]
    assert content["actor"].startswith("provider:")
    assert "engineer" not in content["actor"]


def test_a_provider_handle_is_stable_so_one_engineer_is_not_mistaken_for_three(tmp_path):
    log = _log(tmp_path)
    for _ in range(3):
        log.record("device.update", actor="same-person", actor_kind=ACTOR_PROVIDER, outcome=OUTCOME_SUCCESS)
    log.record("device.update", actor="other-person", actor_kind=ACTOR_PROVIDER, outcome=OUTCOME_SUCCESS)

    handles = [r["content"]["actor"] for r in log.read()]
    assert len(set(handles)) == 2  # three acts by one person, one by another


def test_a_tenant_actor_is_not_pseudonymized_to_themselves(tmp_path):
    log = _log(tmp_path)
    log.record("device.update", actor="alice@acme.example", actor_kind=ACTOR_TENANT, outcome=OUTCOME_SUCCESS)
    assert log.read()[0]["content"]["actor"] == "alice@acme.example"


def test_without_a_pseudonym_key_a_provider_identity_is_withheld_not_leaked(tmp_path):
    """Fail closed: an unkeyed handle would be reversible by dictionary attack."""
    log = _log(tmp_path, pseudonym_key=None)
    log.record("device.update", actor="engineer@provider.example", actor_kind=ACTOR_PROVIDER, outcome=OUTCOME_SUCCESS)
    assert log.read()[0]["content"]["actor"] == "provider:unattributed"
    assert "engineer@provider.example" not in (tmp_path / "audit.log").read_text()


# --- actor resolution and outcome mapping -----------------------------------


def test_actor_from_session_shapes():
    assert actor_from_session(None) == ("unauthenticated", ACTOR_TENANT)
    assert actor_from_session({"kind": "password", "role": "admin"}) == ("password:admin", ACTOR_TENANT)
    assert actor_from_session({"kind": "oidc", "sub": "abc"}) == ("abc", ACTOR_TENANT)
    # The provider-plane seam: exercised now so it cannot rot before the plane exists.
    assert actor_from_session({"kind": "oidc", "sub": "eng", "plane": "provider"}) == ("eng", ACTOR_PROVIDER)


def test_denied_is_distinct_from_error():
    assert outcome_for(200) == "success"
    assert outcome_for(401) == "denied"
    assert outcome_for(403) == "denied"
    assert outcome_for(500) == "error"


# --- the wiring -------------------------------------------------------------
#
# Everything above tests audit.py in isolation, which would keep passing if the routers
# never called it. These assert the app actually records.


def _wired_app(tmp_path, monkeypatch):
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "admin-pw")
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.setenv("AUDIT_TENANT", "acme")
    monkeypatch.setenv("AUDIT_CONTENT_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("AUDIT_PSEUDONYM_KEY", "k")
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    from app.main import create_app

    return create_app()


def test_a_mutation_through_the_api_is_recorded(tmp_path, monkeypatch):
    import httpx
    from fastapi.testclient import TestClient

    app = _wired_app(tmp_path, monkeypatch)

    async def _r(method, path, json=None, bearer=None):
        return httpx.Response(200, json={"status": "removed"})

    with TestClient(app) as c:
        app.state.gateway.request = _r
        c.post("/auth/login", json={"password": "admin-pw"})
        assert c.delete("/api/devices/dev0").status_code == 200

    rows = app.state.audit.read(tenant="acme")
    actions = [r["content"]["action"] for r in rows]
    assert "device.delete" in actions
    deleted = next(r["content"] for r in rows if r["content"]["action"] == "device.delete")
    assert deleted["target"] == "dev0"
    assert deleted["outcome"] == OUTCOME_SUCCESS
    assert deleted["actor"] == "password:admin"

    ok, detail = verify_chain(tmp_path / "audit.log")
    assert ok, detail


def test_a_failed_login_is_recorded_as_denied(tmp_path, monkeypatch):
    """The gateway's chain cannot see this — the request never reaches the gateway."""
    from fastapi.testclient import TestClient

    app = _wired_app(tmp_path, monkeypatch)
    with TestClient(app) as c:
        assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401

    rows = app.state.audit.read(tenant="acme")
    assert [r["content"]["action"] for r in rows] == ["auth.login"]
    assert rows[0]["content"]["outcome"] == "denied"
    assert rows[0]["content"]["detail"]["reason"] == "bad_credentials"


def test_reads_are_not_audited_by_the_bff(tmp_path, monkeypatch):
    """Deliberate: per-user OIDC relay means the gateway's own chain already has them.

    This is the assertion that will need revisiting when provider federation lands —
    at that point a read by a human provider principal becomes tenant-visible (§9).
    """
    import httpx
    from fastapi.testclient import TestClient

    app = _wired_app(tmp_path, monkeypatch)

    async def _g(path, bearer=None):
        return httpx.Response(200, json={"devices": []})

    with TestClient(app) as c:
        app.state.gateway.get = _g
        c.post("/auth/login", json={"password": "admin-pw"})
        assert c.get("/api/devices").status_code == 200

    actions = [r["content"]["action"] for r in app.state.audit.read(tenant="acme")]
    assert actions == ["auth.login"]  # the login, and nothing for the read
