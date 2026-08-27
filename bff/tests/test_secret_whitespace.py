# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Secrets delivered through the environment must survive a trailing newline.

`kubectl create secret --from-file=UI_ADMIN_PASSWORD=pw.txt` — the documented way to build
these — carries the file's trailing newline into the environment variable. The password a
human types into the login form never has one, so an unstripped read makes the *correct*
password fail as "Invalid credentials": the one message that sends an operator off to
re-check a password that was right all along, on the break-glass path they only reached for
because something else was already broken.

Found in a browser against a real deployment, not by the suite. Every existing login test
injects the password directly into `Settings`, where the newline cannot exist — the fixture
made the bug unreachable. These tests go through the environment on purpose.
"""

import pytest
from fastapi.testclient import TestClient

from app.config import _secret, load_settings
from app.main import create_app

# --- _secret: the env branch strips, like the file branch always has -----------


def test_secret_strips_env_branch(monkeypatch):
    monkeypatch.setenv("GATEWAY_API_TOKEN", "from-env\n")
    monkeypatch.delenv("GATEWAY_TOKEN_FILE", raising=False)
    assert _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE") == "from-env"


def test_secret_env_and_file_agree_on_the_same_material(monkeypatch, tmp_path):
    """The divergence this closes: the same key delivered two supported ways used to
    produce two different values, because only the file branch stripped."""
    f = tmp_path / "key"
    f.write_text("shared-material\n")
    monkeypatch.setenv("GATEWAY_TOKEN_FILE", str(f))

    monkeypatch.delenv("GATEWAY_API_TOKEN", raising=False)
    from_file = _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE")

    monkeypatch.setenv("GATEWAY_API_TOKEN", "shared-material\n")
    from_env = _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE")

    assert from_env == from_file == "shared-material"


def test_secret_whitespace_only_env_falls_through_to_file(monkeypatch, tmp_path):
    """A var set to just a newline is empty, not a secret -- it must not shadow the file."""
    f = tmp_path / "key"
    f.write_text("real-key")
    monkeypatch.setenv("GATEWAY_API_TOKEN", "\n")
    monkeypatch.setenv("GATEWAY_TOKEN_FILE", str(f))
    assert _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE") == "real-key"


# --- load_settings: the values compared against what a client sends ------------


@pytest.mark.parametrize("tainted", ["pw\n", "pw\r\n", " pw ", "pw\t"])
def test_passwords_are_normalised(monkeypatch, tainted):
    monkeypatch.setenv("UI_ADMIN_PASSWORD", tainted)
    monkeypatch.setenv("UI_VIEWER_PASSWORD", tainted)
    s = load_settings()
    assert s.ui_admin_password == "pw"
    assert s.ui_viewer_password == "pw"


def test_session_secret_is_normalised(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "signing-key\n")
    assert load_settings().session_secret == "signing-key"


# --- the end-to-end case: what a browser actually sends ------------------------


def test_login_succeeds_with_a_newline_in_the_deployed_secret(monkeypatch):
    """The regression, at the layer it was found: the deployment's env var has the
    newline, the browser posts the clean password, and login must succeed.

    Asserting on `load_settings()` alone would not be enough -- it would prove the value
    was stripped somewhere, not that the comparison a real login performs now matches.
    """
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "4vp-9njpWdzrlikvivSi2h5M\n")
    monkeypatch.setenv("UI_VIEWER_PASSWORD", "viewer-pw\n")
    monkeypatch.setenv("SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as c:
        ok = c.post("/auth/login", json={"password": "4vp-9njpWdzrlikvivSi2h5M"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["role"] == "admin"

        # The viewer password must still land on viewer, not admin -- stripping must not
        # collapse the two roles onto whichever one is checked first.
        vc = TestClient(create_app())
        assert vc.post("/auth/login", json={"password": "viewer-pw"}).json()["role"] == "viewer"


def test_a_password_that_really_is_wrong_is_still_refused(monkeypatch):
    """The negative half. Stripping must not turn into 'close enough' -- without this,
    a fix that returned the role unconditionally would pass every test above."""
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "correct-pw\n")
    monkeypatch.delenv("UI_VIEWER_PASSWORD", raising=False)
    monkeypatch.setenv("SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as c:
        assert c.post("/auth/login", json={"password": "wrong-pw"}).status_code == 401
        # And the newline is not a password of its own once stripped away.
        assert c.post("/auth/login", json={"password": "correct-pw\n"}).status_code == 401


def test_an_unset_password_does_not_authenticate_an_empty_string(monkeypatch):
    """Disabling a role by leaving its password empty must survive normalisation: a var
    set to whitespace strips to "", which must read as 'disabled', never as a match."""
    monkeypatch.setenv("UI_ADMIN_PASSWORD", "   ")
    monkeypatch.delenv("UI_VIEWER_PASSWORD", raising=False)
    monkeypatch.setenv("SESSION_SECRET", "test-secret")

    with TestClient(create_app()) as c:
        assert c.post("/auth/login", json={"password": ""}).status_code == 401
        assert c.post("/auth/login", json={"password": "   "}).status_code == 401
