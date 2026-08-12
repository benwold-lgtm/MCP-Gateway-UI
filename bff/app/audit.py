# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tamper-evident audit for the BFF (gateway F-57 model, ADR-0013 §9/§10).

The gateway already hash-chains its own audit. The BFF needs its own because once
provider federation ships (ADR-0012), the gateway no longer sees the real human: it
sees whatever credential the BFF presented. Today per-user OIDC relay hides that gap.
Federation ends it, so the BFF becomes the only component that can attribute an action
to a person — and an unchained log is not attribution, it is a claim.

Three properties, and the tension between them is the whole design:

**1. The chain is tamper-evident.** Each record commits to ``sha256(seq, prev, payload)``
and links to its predecessor, so editing, deleting or reordering any record is detectable
by replay. Records are tagged with an instance id and verified as one sub-chain *per
writer*, because several BFF replicas appending to one sink would otherwise look like
tampering (the same reasoning as the gateway's ``audit_instance``).

**2. The actor is pseudonymized at WRITE time** (ADR-0013 §9), never at render time. A
record naming a provider engineer in the clear is readable by anyone who can read the
chain, whatever a console chooses to display — and a hash-chained record cannot be
redacted afterwards without breaking verification for everything after it. So the
substitution has to happen before the bytes are committed. :class:`Pseudonymizer` gives a
*stable* handle (same person → same handle), so a tenant can see "the same engineer, three
times" without learning who.

**3. Content is encrypted under a PER-TENANT key** (ADR-0013 §10), so offboarding a tenant
is a key destruction rather than a row deletion. Deleting one tenant's records from a
chain that spans tenants would break verification for every record after them; destroying
their content key leaves the chain intact and the content unrecoverable.

**The decision that makes (1) and (3) coexist: the hash covers the CIPHERTEXT, not the
plaintext.** Hashing plaintext would make the chain unverifiable the moment a tenant was
shredded — the verifier could no longer recompute what it committed to — which is exactly
when you most need to prove the log was not tampered with. So encryption happens first and
the chain commits to the sealed bytes.

**What survives a shred, stated honestly.** The tenant tag, timestamp and chain position
stay in the clear: the tenant tag is how the reader knows which key applies, and the chain
fields are what make verification possible at all. After a shred you can still see that
tenant X performed N audited actions at particular times. That is inherent to
crypto-shredding rather than an oversight, and it is the price of keeping the chain
verifiable. Nothing about *what* was done, *to what*, or *by whom* survives.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

RECORD_VERSION = 1
EVENT_NAME = "bff.audit"

OUTCOME_SUCCESS = "success"
OUTCOME_DENIED = "denied"
OUTCOME_ERROR = "error"

ACTOR_TENANT = "tenant"
ACTOR_PROVIDER = "provider"

ENC_FERNET = "fernet"
ENC_NONE = "none"

_GENESIS = "0" * 64

# Chain framing, excluded from the hashed payload (they *are* the commitment).
_CHAIN_FIELDS = frozenset({"seq", "prev", "hash"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_instance_id() -> str:
    """Stable id for this replica's audit sub-chain.

    Prefer an orchestrator-stable value so the chain survives a restart; the per-process
    fallback simply starts a fresh sub-chain, which verifies on its own but cannot be
    linked to what this replica wrote before.
    """
    return os.getenv("BFF_INSTANCE_ID") or os.getenv("HOSTNAME") or f"local-{uuid.uuid4().hex[:8]}"


def _record_hash(seq: int, prev: str, payload: dict[str, Any]) -> str:
    """sha256 over the sequence number, the previous hash, and a canonical serialisation
    of the payload. The verifier recomputes this identically, so any edit, reorder or
    deletion breaks the chain."""
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{seq}\n{prev}\n{canon}".encode()).hexdigest()


class Pseudonymizer:
    """Stable, non-reversible actor handles (ADR-0013 §9).

    Keyed HMAC rather than a bare hash: a bare hash of a subject is trivially reversible
    by dictionary attack over a known staff list, which would make the pseudonym
    decorative. Stability matters as much as opacity — a tenant reviewing their audit
    should be able to tell one engineer from two.

    A tenant principal acting inside their own tenant is **not** pseudonymized: they are
    already entitled to know who they are, and obscuring it would make their own audit
    useless to them. Only cross-plane actors get a handle.
    """

    def __init__(self, key: bytes | None) -> None:
        self._key = key

    def handle(self, subject: str, *, actor_kind: str) -> str:
        if actor_kind != ACTOR_PROVIDER:
            return subject
        if not self._key:
            # No key configured: refuse to emit the real identity of a cross-plane actor
            # into a tenant-readable chain. An opaque constant is a worse audit record but
            # a far better failure than a silent disclosure that cannot be retracted.
            return "provider:unattributed"
        digest = hmac.new(self._key, subject.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"provider:{digest[:16]}"


class TenantKeyring:
    """Per-tenant content keys (ADR-0013 §10).

    ``shred`` is deliberately irreversible in-process: it drops the key so subsequent
    reads cannot decrypt that tenant's history. Destroying the *persisted* key is an
    operational step (secret store / KMS); this class is the enforcement point in the
    writer, not the key custodian.
    """

    def __init__(self, keys: dict[str, bytes] | None = None) -> None:
        self._keys: dict[str, Any] = {}
        for tenant, raw in (keys or {}).items():
            self._keys[tenant] = self._build(raw)

    @staticmethod
    def _build(raw: bytes) -> Any:
        from cryptography.fernet import Fernet

        return Fernet(raw)

    def add(self, tenant: str, raw: bytes) -> None:
        self._keys[tenant] = self._build(raw)

    def shred(self, tenant: str) -> bool:
        """Forget a tenant's content key. Returns True if a key was present."""
        return self._keys.pop(tenant, None) is not None

    def seal(self, tenant: str, payload: dict[str, Any]) -> tuple[str, Any]:
        """Return ``(enc, content)`` — ciphertext when a key exists, else plaintext.

        Running without a key is supported so an existing deployment keeps auditing after
        an upgrade rather than failing closed on a missing secret, but it forfeits the
        ability to crypto-shred that tenant. The caller surfaces that at startup.
        """
        key = self._keys.get(tenant)
        if key is None:
            return ENC_NONE, payload
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return ENC_FERNET, key.encrypt(blob).decode("ascii")

    def open(self, tenant: str, enc: str, content: Any) -> dict[str, Any] | None:
        """Decrypt a record's content, or None when it cannot be read.

        None is the expected result for a shredded tenant — the caller distinguishes
        "unreadable" from "absent" rather than treating it as corruption.
        """
        if enc == ENC_NONE:
            return content if isinstance(content, dict) else None
        key = self._keys.get(tenant)
        if key is None or not isinstance(content, str):
            return None
        try:
            return json.loads(key.decrypt(content.encode("ascii")).decode("utf-8"))
        except Exception:
            return None


class _Chain:
    """In-process append-only hash chain."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = _GENESIS

    def advance(self, payload: dict[str, Any]) -> tuple[int, str, str]:
        with self._lock:
            seq, prev = self._seq, self._prev
            h = _record_hash(seq, prev, payload)
            self._seq, self._prev = seq + 1, h
            return seq, prev, h

    def seed(self, *, next_seq: int, prev: str) -> None:
        with self._lock:
            self._seq, self._prev = next_seq, prev


class AuditLog:
    """The BFF's audit writer.

    Attached to ``app.state.audit``. One instance per process; the chain is per instance
    and re-seeds from this instance's own tail on startup so a restart continues the
    sub-chain instead of looking like a reset.
    """

    def __init__(
        self,
        *,
        path: str | os.PathLike[str] | None,
        tenant: str,
        keyring: TenantKeyring | None = None,
        pseudonymizer: Pseudonymizer | None = None,
        instance_id: str | None = None,
        echo: bool = True,
    ) -> None:
        self.path = Path(path) if path else None
        self.tenant = tenant
        self.keyring = keyring or TenantKeyring()
        self.pseudonymizer = pseudonymizer or Pseudonymizer(None)
        self.instance_id = instance_id or resolve_instance_id()
        self._echo = echo
        self._chain = _Chain()
        self._write_lock = threading.Lock()
        if self.path:
            self._seed_from_tail()

    # -- writing ------------------------------------------------------------

    def record(
        self,
        action: str,
        *,
        actor: str,
        outcome: str,
        actor_kind: str = ACTOR_TENANT,
        tenant: str | None = None,
        target: str | None = None,
        rid: str | None = None,
        **detail: Any,
    ) -> dict[str, Any]:
        """Append one audit record. Returns the record as written (content sealed)."""
        tenant_id = tenant or self.tenant
        payload = {
            "action": action,
            "actor": self.pseudonymizer.handle(actor, actor_kind=actor_kind),
            "actor_kind": actor_kind,
            "outcome": outcome,
            "target": target,
            "rid": rid,
        }
        if detail:
            payload["detail"] = detail

        enc, content = self.keyring.seal(tenant_id, payload)
        # Everything below the chain fields is what the hash commits to. `content` is
        # already sealed at this point — see the module docstring on why the commitment
        # is over ciphertext.
        framed: dict[str, Any] = {
            "v": RECORD_VERSION,
            "event": EVENT_NAME,
            "instance": self.instance_id,
            "ts": _now(),
            "tenant": tenant_id,
            "enc": enc,
            "content": content,
        }
        seq, prev, digest = self._chain.advance(framed)
        rec = {**framed, "seq": seq, "prev": prev, "hash": digest}
        self._emit(rec)
        return rec

    def _emit(self, rec: dict[str, Any]) -> None:
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str)
        if self.path:
            with self._write_lock:
                try:
                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError as exc:  # pragma: no cover - depends on the filesystem
                    print(f"[audit] could not write {self.path}: {exc}", flush=True)
        if self._echo:
            print(line, flush=True)

    def _seed_from_tail(self) -> None:
        last = _last_record(self.path, instance=self.instance_id)
        if last and isinstance(last.get("seq"), int) and isinstance(last.get("hash"), str):
            self._chain.seed(next_seq=last["seq"] + 1, prev=last["hash"])

    # -- reading ------------------------------------------------------------

    def read(self, *, tenant: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Recent records, newest first, with content opened where the key allows.

        A record whose content cannot be decrypted is returned with ``"content": None``
        and ``"readable": false`` rather than omitted — a shredded tenant's activity
        should still be visibly *present* in the chain.
        """
        if not self.path:
            return []
        wanted = tenant or self.tenant
        out: list[dict[str, Any]] = []
        for rec in reversed(list(_iter_records(self.path))):
            if rec.get("tenant") != wanted:
                continue
            opened = self.keyring.open(wanted, rec.get("enc", ENC_NONE), rec.get("content"))
            out.append(
                {
                    "seq": rec.get("seq"),
                    "ts": rec.get("ts"),
                    "tenant": rec.get("tenant"),
                    "instance": rec.get("instance"),
                    "readable": opened is not None,
                    "content": opened,
                }
            )
            if len(out) >= limit:
                break
        return out


# -- verification -----------------------------------------------------------


def _iter_records(path: str | os.PathLike[str]) -> Iterable[dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("event") == EVENT_NAME:
                    yield rec
    except OSError:
        return


def _last_record(path: str | os.PathLike[str] | None, *, instance: str) -> dict[str, Any] | None:
    if not path:
        return None
    last = None
    for rec in _iter_records(path):
        if rec.get("instance") == instance:
            last = rec
    return last


def verify_chain(path: str | os.PathLike[str]) -> tuple[bool, str]:
    """Replay a BFF audit log and verify every sub-chain in it.

    Returns ``(ok, detail)``. Detects an altered record (recomputed hash differs), a
    deleted or reordered one (``prev`` no longer matches the predecessor's hash), and a
    sequence gap. Each instance is verified independently, so interleaved replicas are
    not mistaken for tampering.

    **Verification does not need any content key.** It recomputes over the sealed bytes,
    so a shredded tenant's records still verify — which is the point of committing to
    ciphertext.
    """
    heads: dict[str, tuple[int, str]] = {}
    count = 0
    for rec in _iter_records(path):
        inst = rec.get("instance", "")
        seq, prev, digest = rec.get("seq"), rec.get("prev"), rec.get("hash")
        if not isinstance(seq, int) or not isinstance(prev, str) or not isinstance(digest, str):
            return False, f"record {count} in {inst!r} is missing chain fields"

        payload = {k: v for k, v in rec.items() if k not in _CHAIN_FIELDS}
        if _record_hash(seq, prev, payload) != digest:
            return False, f"record seq={seq} instance={inst!r} fails its own hash (altered)"

        if inst in heads:
            exp_seq, exp_prev = heads[inst]
            if seq != exp_seq:
                return False, f"sequence gap in instance {inst!r}: expected seq={exp_seq}, got {seq}"
            if prev != exp_prev:
                return False, f"broken link at seq={seq} in instance {inst!r} (record deleted or reordered)"
        heads[inst] = (seq + 1, digest)
        count += 1

    if count == 0:
        return True, "no audit records"
    return True, f"verified {count} record(s) across {len(heads)} instance(s)"


# -- actor resolution -------------------------------------------------------


def actor_from_session(session: dict[str, Any] | None) -> tuple[str, str]:
    """``(subject, actor_kind)`` for an audit record.

    Password sessions are local break-glass logins, so the *role* is the most specific
    identity that exists — recorded as ``password:<role>`` rather than a name the BFF
    does not have. OIDC sessions carry the IdP subject, which is the real human.

    ``actor_kind`` is where the provider plane will attach: a session authenticated
    against the provider IdP resolves to :data:`ACTOR_PROVIDER` and is pseudonymized on
    the way into the chain. Until that plane exists every session is a tenant principal,
    but the seam is exercised rather than hypothetical — see the pseudonymizer tests.
    """
    if not session:
        return "unauthenticated", ACTOR_TENANT
    if session.get("plane") == ACTOR_PROVIDER:
        return str(session.get("sub") or "unknown"), ACTOR_PROVIDER
    if session.get("kind") == "oidc":
        return str(session.get("sub") or "unknown"), ACTOR_TENANT
    return f"password:{session.get('role') or 'unknown'}", ACTOR_TENANT


def outcome_for(status_code: int) -> str:
    """Map an upstream HTTP status onto an audit outcome.

    401/403 are ``denied`` rather than ``error`` because "who was refused what" is the
    question an audit is most often asked, and collapsing it into a generic failure is
    what makes a log unanswerable after an incident.
    """
    if status_code in (401, 403):
        return OUTCOME_DENIED
    return OUTCOME_SUCCESS if status_code < 400 else OUTCOME_ERROR


async def record_request(request: Any, action: str, *, outcome: str, target: str | None = None, **detail: Any) -> None:
    """Audit an HTTP action, resolving the actor from the request's session.

    A no-op when no audit log is attached, so a partially-constructed app (tests that
    build a bare router) does not fail on an unrelated concern. Failures inside the
    writer are swallowed for the same reason a request should not 500 because its audit
    sink is full — the writer itself reports the problem.
    """
    log = getattr(getattr(request, "app", None), "state", None)
    log = getattr(log, "audit", None)
    if log is None:
        return
    from .security import current_session

    try:
        session = await current_session(request)
        actor, actor_kind = actor_from_session(session)
        log.record(
            action,
            actor=actor,
            actor_kind=actor_kind,
            outcome=outcome,
            target=target,
            rid=request.headers.get("x-request-id"),
            **detail,
        )
    except Exception as exc:  # pragma: no cover - defensive; the writer reports its own
        print(f"[audit] failed to record {action!r}: {exc}", flush=True)
