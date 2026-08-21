# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""TM-I-05: the discovery document must declare the issuer it was fetched from.

Without the check in ``_discover``, ``validate_id_token`` validates the ID token against
``meta["issuer"]`` — whatever the document said — so the threat model's "issuer pinned in
config" is pinned to the response instead. The gateway half pins against its own config;
this is the BFF half catching up.

The refusal cases below are stubbed, because serving a *lying* discovery document is not
something a real IdP will do on request. The acceptance case deliberately is not: a stub
that happens to match the normalisation this code does would pass whether or not the
normalisation is right, which is the blind spot this project has been bitten by before. It
runs against the real lab Keycloak when ``LAB_OIDC_ISSUER`` is set, and skips otherwise.
"""

import os

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
os.environ.setdefault("SESSION_SECRET", "test-secret")

from dataclasses import dataclass  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.oidc import OIDCClient, OIDCError  # noqa: E402


@dataclass
class _S:
    oidc_issuer: str
    oidc_client_id: str = "bff"
    oidc_client_secret: str = ""
    oidc_redirect_url: str = "https://ui.example.com/auth/oidc/callback"
    oidc_scopes: str = "openid profile email"


def _doc(issuer: str) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/auth",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/certs",
    }


def _serve(doc: dict, monkeypatch) -> None:
    """Make every discovery GET return ``doc``."""

    async def _get(self, url, *a, **kw):
        return httpx.Response(200, json=doc, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", _get)


@pytest.mark.asyncio
async def test_declared_issuer_must_match_config(monkeypatch):
    """A document naming a different issuer is refused, not quietly trusted."""
    _serve(_doc("https://evil.example.com/realms/x"), monkeypatch)
    client = OIDCClient(_S(oidc_issuer="https://idp.example.com/realms/tenant-a"))
    with pytest.raises(OIDCError) as exc:
        await client._discover()
    assert "issuer mismatch" in str(exc.value)
    # The real point: nothing was memoised, so a later call cannot pick up the rejected
    # document from cache.
    assert client._meta is None
    assert client._jwks is None


@pytest.mark.asyncio
async def test_absent_issuer_is_refused(monkeypatch):
    """A document with no `issuer` at all fails closed rather than comparing to ''."""
    doc = _doc("https://idp.example.com/realms/tenant-a")
    del doc["issuer"]
    _serve(doc, monkeypatch)
    client = OIDCClient(_S(oidc_issuer="https://idp.example.com/realms/tenant-a"))
    with pytest.raises(OIDCError):
        await client._discover()


@pytest.mark.asyncio
async def test_prefix_collision_is_refused(monkeypatch):
    """`.../tenant-a` must not accept a document from `.../tenant-attacker`.

    A substring or `startswith` comparison would pass this. Exact match is the requirement.
    """
    _serve(_doc("https://idp.example.com/realms/tenant-attacker"), monkeypatch)
    client = OIDCClient(_S(oidc_issuer="https://idp.example.com/realms/tenant-a"))
    with pytest.raises(OIDCError):
        await client._discover()


@pytest.mark.asyncio
async def test_trailing_slash_is_not_a_mismatch(monkeypatch):
    """A config-style difference must not become a refusal."""
    _serve(_doc("https://idp.example.com/realms/tenant-a"), monkeypatch)
    client = OIDCClient(_S(oidc_issuer="https://idp.example.com/realms/tenant-a/"))
    meta = await client._discover()
    assert meta["issuer"] == "https://idp.example.com/realms/tenant-a"


@pytest.mark.asyncio
async def test_real_idp_still_passes():
    """The happy path, against an IdP nobody here wrote.

    Set ``LAB_OIDC_ISSUER`` to a real realm URL, e.g.
    ``http://kc.192-168-1-216.nip.io:8080/realms/tenant-a``.
    """
    issuer = os.getenv("LAB_OIDC_ISSUER")
    if not issuer:
        pytest.skip("LAB_OIDC_ISSUER not set — no real IdP to check the acceptance path against")
    client = OIDCClient(_S(oidc_issuer=issuer))
    meta = await client._discover()
    assert meta["issuer"].rstrip("/") == issuer.rstrip("/")
    assert client._jwks is not None
