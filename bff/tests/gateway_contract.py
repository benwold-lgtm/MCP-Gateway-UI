# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""A fake gateway that refuses what the real one refuses (LR-50).

Every BFF test until now replaced the gateway with a double that returned 201 for any body.
That double is more permissive than any gateway that has ever run, so the console↔gateway
contract was asserted on one side only: the suite could prove what the BFF *does with a
response* and never what it is *entitled to send*. Two 🔴 defects lived in exactly that gap
and were found by deploying into a lab rather than by CI:

* **LR-48** — the claim path sent `upstream_transport` on every registration. The gateway
  refuses it on an openapi device *on the presence of the key*, so the catalog's own default
  of `"http"` was rejected as though it were a wrong value. **No OpenAPI device type had ever
  been claimable**, since 2026-08-11.
* **LR-49** — on a `require_references: true` deployment the claim path sends the tenant's key
  inline and the gate refuses it, so no credential-bearing type is claimable at all.

So this double enforces the registration rules instead of waving them through. It is a
**transcription**, and transcriptions drift, which is stated here rather than hoped away:

    SOURCE OF TRUTH: device_mcp_gateway/registry/validation.py
    Synced 2026-09-01 against that file's 11 refusals. Only the rules the BFF can actually
    violate are implemented — hostname shape, URL policy and the rate-limit form are the
    caller's own input and are covered by the gateway's suite.

The rule this file exists to defend is not any single refusal: it is that **a fake upstream
must not be more permissive than the real one**, because a suite built on a permissive fake
proves the half of the contract that was never in doubt.

**Why this is not used by every test that reaches `/api/devices`.** Those suites test auth,
plane isolation and audit, and their registration bodies are ones a *tenant typed*; the
gateway's own suite owns whether it accepts them, and refusing here would add failures
unrelated to what those tests are for. The claim path is different in kind: its body is
**assembled by the BFF** from a catalog version, so nobody reviews it and no tenant can
correct it. A machine-generated body sent to a validating endpoint is exactly where a
permissive double stops being a convenience and starts hiding things — which is what
happened. Use this double wherever the BFF composes the body itself.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

#: Fields whose presence — not value — the gateway refuses on an openapi device.
_MCP_ONLY_FIELDS = ("upstream_transport",)
#: Fields the gateway refuses on an mcp device.
_OPENAPI_ONLY_FIELDS = ("spec_url",)

_INLINE_SECRET_FIELDS = ("api_key", "password", "client_secret", "token")


class GatewayRefused(Exception):
    """Raised only inside this module; callers see the 400 the gateway would return."""


def check_registration(body: dict[str, Any], *, require_references: bool = False) -> Optional[str]:
    """Return the gateway's refusal detail for this body, or ``None`` if it would be accepted.

    Mirrors `registry/validation.py`. Kept as a function rather than folded into the fake so a
    test can assert against the contract directly, and so the transcription has one home.
    """
    transport = body.get("transport", "sse")
    if transport != "sse":
        return f"Transport '{transport}' is not supported in gateway mode; use 'sse'"

    kind = body.get("upstream_kind", "openapi")
    if kind not in ("openapi", "mcp"):
        return f"upstream_kind '{kind}' is not recognised; use one of openapi, mcp"

    upstream_transport = body.get("upstream_transport", "http")
    if upstream_transport not in ("http", "sse"):
        return f"upstream_transport '{upstream_transport}' is not recognised; use one of http, sse"

    # Presence, not value — this is the LR-48 rule, and writing it as a value check here
    # would reproduce the defect inside the thing meant to catch it.
    if kind == "openapi":
        for field in _MCP_ONLY_FIELDS:
            if field in body:
                return f"{field} applies only to upstream_kind 'mcp'; an OpenAPI device is reached over HTTP"
    if kind == "mcp":
        for field in _OPENAPI_ONLY_FIELDS:
            if body.get(field):
                return f"{field} does not apply to upstream_kind 'mcp'; a proxied MCP server has no OpenAPI document"
        if upstream_transport == "sse":
            return "upstream_transport 'sse' is not yet supported; use 'http' (Streamable HTTP)"

    if require_references:
        auth = body.get("auth") or {}
        inline = [f for f in _INLINE_SECRET_FIELDS if auth.get(f)]
        if inline:
            return (
                f"this deployment requires credentials by reference (ADR-0018 §1) and this device "
                f"supplies {', '.join(inline)} inline."
            )
    return None


class ContractGateway:
    """Drop-in for the permissive `_FakeGateway`, with the refusals in place.

    ``require_references`` is the deployment posture ADR-0018 §1 recommends and this lab runs.
    It defaults to **off**, matching the gateway's own default, so turning it on in a test is
    a visible statement about which deployment is being modelled.
    """

    def __init__(self, *, status: int = 201, payload: Any = None, require_references: bool = False):
        self.status = status
        self.payload = payload if payload is not None else {"hostname": "sensor-01"}
        self.require_references = require_references
        self.calls: list[dict] = []
        self.refusals: list[str] = []

    async def request(self, method, path, json=None, bearer=None, headers=None):
        self.calls.append({"method": method, "path": path, "json": json})
        if method == "POST" and path.rstrip("/").endswith("/devices") and isinstance(json, dict):
            refusal = check_registration(json, require_references=self.require_references)
            if refusal:
                self.refusals.append(refusal)
                return httpx.Response(400, json={"detail": refusal})
        return httpx.Response(self.status, json=self.payload)
