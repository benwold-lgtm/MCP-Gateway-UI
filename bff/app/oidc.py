# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""OIDC Relying-Party for the BFF — Authorization Code + PKCE (ADR-0007, boundaries I1/I2).

The BFF logs the user in against the IdP and obtains tokens server-side; the browser
never sees them (they live in the server-side session store). This module owns the IdP
conversation: discovery, the authorization redirect (with PKCE + ``state`` + ``nonce``),
the code→token exchange, and **ID-token validation** (signature via the IdP's JWKS,
``iss``/``aud``/``exp`` and ``nonce``).

Threat-model alignment (docs/threat-model-identity.md):
  * **TM-I-06** — Authorization Code + PKCE (S256); the code is exchanged server-side.
  * **TM-I-01** — ``state`` + ``nonce`` are generated here and verified by the caller
    against the session, defeating login-CSRF and token replay into the session.
  * **TM-I-05** — discovery/JWKS/token endpoints are the issuer's HTTPS endpoints; the
    ID token is signature-checked with an asymmetric-only algorithm allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass

import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

import httpx
import jwt
from fastapi.concurrency import run_in_threadpool

from .config import Settings

# Asymmetric only — a BFF must never accept an HS*/none-signed ID token (TM-I-05/08).
_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

# at_hash uses the hash whose size matches the signature alg (…256→SHA-256, etc.).
_AT_HASH_DIGESTS = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}

_HTTP_TIMEOUT = 10.0


class OIDCError(Exception):
    """Login could not be completed (discovery, token exchange, or validation failed)."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _at_hash_matches(alg: str, access_token: str, expected: str) -> bool:
    """True if ``expected`` is the OIDC ``at_hash`` of ``access_token`` for ``alg``.

    at_hash = base64url(left-most half of the alg-sized hash of the ASCII access token)
    (OIDC Core §3.1.3.6). Compared in constant time."""
    digestmod = _AT_HASH_DIGESTS.get(alg[-3:])
    if digestmod is None:
        return False
    digest = digestmod(access_token.encode("ascii")).digest()
    computed = _b64url(digest[: len(digest) // 2])
    return secrets.compare_digest(computed, expected)


def make_pkce_pair() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` for PKCE S256."""
    verifier = _b64url(os.urandom(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


@dataclass(frozen=True)
class _ProviderView:
    """The provider IdP's settings under the field names :class:`OIDCClient` reads.

    An adapter rather than a parallel client: the provider plane needs the *same* RP
    behaviour (discovery, PKCE, at_hash, RP-initiated logout) against a *different* IdP,
    and a second implementation of that is a second place for a verification step to go
    missing. ADR-0013 §2 makes these separate populations, not separate protocols.
    """

    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_url: str
    oidc_scopes: str


class OIDCClient:
    """Per-app OIDC RP. Discovery + JWKS are fetched lazily and memoised."""

    def __init__(self, settings) -> None:
        if not settings.oidc_issuer or not settings.oidc_client_id or not settings.oidc_redirect_url:
            raise ValueError("OIDC is enabled but OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_REDIRECT_URL must all be set")
        self._s = settings
        self._meta: dict | None = None
        self._jwks: jwt.PyJWKClient | None = None

    @classmethod
    def for_provider(cls, settings: Settings) -> "OIDCClient":
        """The provider-plane RP (ADR-0013 §2), built from the PROVIDER_OIDC_* settings."""
        if (
            not settings.provider_oidc_issuer
            or not settings.provider_oidc_client_id
            or not settings.provider_oidc_redirect_url
        ):
            raise ValueError(
                "The provider plane is enabled but PROVIDER_OIDC_ISSUER, PROVIDER_OIDC_CLIENT_ID "
                "and PROVIDER_OIDC_REDIRECT_URL must all be set"
            )
        return cls(
            _ProviderView(
                oidc_issuer=settings.provider_oidc_issuer,
                oidc_client_id=settings.provider_oidc_client_id,
                oidc_client_secret=settings.provider_oidc_client_secret,
                oidc_redirect_url=settings.provider_oidc_redirect_url,
                oidc_scopes=settings.provider_oidc_scopes,
            )
        )

    async def _discover(self) -> dict:
        if self._meta is None:
            url = self._s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                meta = resp.json()
            if not meta.get("authorization_endpoint") or not meta.get("token_endpoint") or not meta.get("jwks_uri"):
                raise OIDCError("OIDC discovery document is missing required endpoints")
            self._meta = meta
            # PyJWKClient caches keys and refreshes on an unseen kid (sync; we run it in
            # a threadpool from the async callback so the event loop is never blocked).
            self._jwks = jwt.PyJWKClient(meta["jwks_uri"])
        return self._meta

    async def authorization_url(self, *, state: str, nonce: str, challenge: str) -> str:
        meta = await self._discover()
        params = {
            "response_type": "code",
            "client_id": self._s.oidc_client_id,
            "redirect_uri": self._s.oidc_redirect_url,
            "scope": self._s.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{meta['authorization_endpoint']}?{urlencode(params)}"

    async def exchange_code(self, *, code: str, verifier: str) -> dict:
        """Exchange the authorization code for tokens at the token endpoint."""
        meta = await self._discover()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._s.oidc_redirect_url,
            "client_id": self._s.oidc_client_id,
            "code_verifier": verifier,
        }
        # Confidential clients authenticate with HTTP Basic; public clients rely on PKCE.
        auth = (self._s.oidc_client_id, self._s.oidc_client_secret) if self._s.oidc_client_secret else None
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(meta["token_endpoint"], data=data, auth=auth)
        if resp.status_code != 200:
            raise OIDCError(f"token endpoint returned {resp.status_code}: {resp.text[:200]}")
        tokens = resp.json()
        if not tokens.get("id_token"):
            raise OIDCError("token response has no id_token")
        return tokens

    async def refresh_tokens(self, *, refresh_token: str) -> dict:
        """Exchange a refresh token for a fresh token set at the token endpoint.

        The IdP may return a rotated ``refresh_token`` and/or a new ``id_token`` alongside
        the new ``access_token``; the caller persists whatever comes back. Scope is omitted
        so the IdP re-issues the originally granted scopes."""
        meta = await self._discover()
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._s.oidc_client_id,
        }
        auth = (self._s.oidc_client_id, self._s.oidc_client_secret) if self._s.oidc_client_secret else None
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(meta["token_endpoint"], data=data, auth=auth)
        if resp.status_code != 200:
            raise OIDCError(f"refresh_token grant returned {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    async def validate_id_token(self, *, id_token: str, nonce: str, access_token: str | None = None) -> dict:
        """Validate the ID token's signature/claims and bind it to ``nonce`` (TM-I-01).

        When the IdP includes ``at_hash`` and we hold the access token, also bind the
        access token to the ID token (OIDC Core §3.1.3.6) so a swapped access token is
        rejected."""
        meta = await self._discover()
        assert self._jwks is not None  # set alongside _meta

        def _decode() -> dict:
            signing_key = self._jwks.get_signing_key_from_jwt(id_token).key
            return jwt.decode(
                id_token,
                signing_key,
                algorithms=_ID_TOKEN_ALGS,
                audience=self._s.oidc_client_id,
                issuer=meta["issuer"],
                options={"require": ["exp", "iat"]},
            )

        try:
            claims = await run_in_threadpool(_decode)
        except jwt.PyJWTError as exc:
            raise OIDCError(f"id_token validation failed: {exc}")
        if claims.get("nonce") != nonce:
            raise OIDCError("id_token nonce mismatch")
        expected_at_hash = claims.get("at_hash")
        if expected_at_hash and access_token:
            alg = jwt.get_unverified_header(id_token).get("alg", "")
            if not _at_hash_matches(alg, access_token, expected_at_hash):
                raise OIDCError("id_token at_hash does not match access_token")
        return claims

    async def end_session_url(self, *, id_token_hint: str, post_logout_redirect_uri: str | None = None) -> str | None:
        """RP-initiated (single) logout URL, or None if the IdP exposes no end_session_endpoint.

        Returning None lets the caller fall back to a local-only logout."""
        meta = await self._discover()
        endpoint = meta.get("end_session_endpoint")
        if not endpoint:
            return None
        params = {"id_token_hint": id_token_hint}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return f"{endpoint}?{urlencode(params)}"
