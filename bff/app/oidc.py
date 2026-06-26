# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""OIDC Relying-Party for the BFF — Authorization Code + PKCE (ADR-0007, boundaries I1/I2).

The BFF logs the user in against the IdP and obtains tokens server-side; the browser
never sees them (they live in the signed-cookie session). This module owns the IdP
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

import base64
import hashlib
import os
from urllib.parse import urlencode

import httpx
import jwt
from fastapi.concurrency import run_in_threadpool

from .config import Settings

# Asymmetric only — a BFF must never accept an HS*/none-signed ID token (TM-I-05/08).
_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

_HTTP_TIMEOUT = 10.0


class OIDCError(Exception):
    """Login could not be completed (discovery, token exchange, or validation failed)."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_pkce_pair() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` for PKCE S256."""
    verifier = _b64url(os.urandom(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class OIDCClient:
    """Per-app OIDC RP. Discovery + JWKS are fetched lazily and memoised."""

    def __init__(self, settings: Settings) -> None:
        if not settings.oidc_issuer or not settings.oidc_client_id or not settings.oidc_redirect_url:
            raise ValueError("OIDC is enabled but OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_REDIRECT_URL must all be set")
        self._s = settings
        self._meta: dict | None = None
        self._jwks: jwt.PyJWKClient | None = None

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

    async def validate_id_token(self, *, id_token: str, nonce: str) -> dict:
        """Validate the ID token's signature/claims and bind it to ``nonce`` (TM-I-01)."""
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
        return claims
