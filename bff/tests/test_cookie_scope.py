# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The session cookie must never leave the host that set it (C8).

The product's per-tenant subdomain model is an isolation boundary *only* while this holds.
A cookie scoped to `.example.com` is sent to every tenant portal beneath it, so one tenant's
browser carries a session into another's console — and nothing appears to break, which is
exactly why it needs a test rather than a comment.

Two paths could widen it, and they need different guards:

* **Configuration** — an operator looking for a cookie-domain knob. `COOKIE_DOMAIN` is read
  for no other reason than to refuse it here, loudly, where the reason can be explained. Left
  unrecognised, the same operator sets it at a reverse proxy instead, where nothing in this
  process can see it.
* **Code** — a `domain=` argument added to `SessionMiddleware` in a later edit. That is
  caught by reading the real `Set-Cookie` header off a real response rather than by
  inspecting how the middleware was constructed: the header is the thing browsers act on,
  and it stays true however the cookie comes to be set.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")


def _base_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "admin-pw")
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "false")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    monkeypatch.delenv("COOKIE_DOMAIN", raising=False)


def _set_cookie_header(client: TestClient) -> str:
    """The real header from a real login, not a description of how it was configured."""
    resp = client.post("/auth/login", json={"password": "admin-pw"})
    assert resp.status_code == 200, resp.text
    header = resp.headers.get("set-cookie")
    assert header, "the login response set no cookie at all — this test would pass vacuously"
    return header


def test_the_session_cookie_is_scoped_to_the_host_that_set_it(monkeypatch, tmp_path):
    """No `Domain=` attribute: the browser sends it back only to this exact host.

    The assertion is on the header a browser receives, so it survives any change in how the
    middleware is wired — including someone passing `domain=` to `SessionMiddleware`, which
    is the edit this exists to catch.
    """
    _base_env(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        header = _set_cookie_header(client)
    assert "domain=" not in header.lower(), header


def test_the_cookie_still_carries_the_other_two_defences(monkeypatch, tmp_path):
    """Host scope is one of three, and a change that quietly dropped either of the others
    would leave this file asserting the wrong thing is safe."""
    _base_env(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        header = _set_cookie_header(client).lower()
    assert "httponly" in header, header
    assert "samesite=lax" in header, header


@pytest.mark.parametrize(
    "value",
    [".example.com", "example.com", "tenant-a.example.com"],
    ids=["parent-wildcard", "parent-bare", "exact-host"],
)
def test_a_configured_cookie_domain_refuses_to_start(monkeypatch, tmp_path, value):
    """Every value, including one naming this very host.

    An exact-host value is only *redundant* rather than dangerous — but accepting it would
    make `COOKIE_DOMAIN` look like a supported knob whose safety depends on getting the value
    right, and the next deployment gets it wrong. Refusing the whole setting is a rule a
    reader can hold; "refuse the unsafe ones" is a judgement call at deploy time.
    """
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("COOKIE_DOMAIN", value)
    with pytest.raises(RuntimeError) as exc:
        create_app()
    # The message must name the consequence, not just the rule. An operator who set this was
    # trying to solve something, and "unset it" alone tells them nothing about why.
    assert "host-scoped" in str(exc.value)
    assert "every tenant" in str(exc.value)


def test_an_empty_or_whitespace_value_is_not_a_setting(monkeypatch, tmp_path):
    """`COOKIE_DOMAIN=` in an env file is an operator *not* setting it. Refusing there would
    make the guard fire on a deployment that is already correct, which is how a fail-closed
    check gets removed."""
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("COOKIE_DOMAIN", "   ")
    with TestClient(create_app()) as client:
        assert "domain=" not in _set_cookie_header(client).lower()
