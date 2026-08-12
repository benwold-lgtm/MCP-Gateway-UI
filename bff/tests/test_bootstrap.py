# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""First-run bootstrap (lite/home): generation, persistence, precedence, and no-op."""

import stat

from cryptography.fernet import Fernet

from app.bootstrap import apply_first_run_bootstrap
from app.config import DEFAULT_SESSION_SECRET, Settings, _secret


def _settings(**over) -> Settings:
    base = dict(
        gateway_url="http://gw:8000",
        gateway_api_prefix="/v1",
        gateway_token="tok",
        ui_admin_password="",
        ui_viewer_password="",
        session_secret=DEFAULT_SESSION_SECRET,
        prometheus_url="",
        loki_url="",
    )
    base.update(over)
    return Settings(**base)


def test_noop_without_state_dir(monkeypatch):
    monkeypatch.delenv("BFF_STATE_DIR", raising=False)
    s = _settings()
    assert apply_first_run_bootstrap(s) is s  # unchanged, nothing written


def test_unwritable_state_dir_degrades_instead_of_crashing(monkeypatch, tmp_path):
    """Regression: a root-owned/read-only mounted volume (e.g. a misconfigured container
    image) must not crash app startup -- it should fall back to the unmodified settings,
    same as the state-dir-missing case. This is exactly the failure mode a Docker named
    volume hits when the image never pre-created + chowned the mount path."""
    monkeypatch.setenv("BFF_STATE_DIR", str(tmp_path))
    tmp_path.chmod(0o500)  # dir exists (mkdir succeeds) but is not writable
    try:
        s = _settings()
        out = apply_first_run_bootstrap(s)
        assert out is s  # unchanged -- no crash, no partial state
    finally:
        tmp_path.chmod(0o700)  # restore so pytest can clean up tmp_path


def test_generates_and_persists(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BFF_STATE_DIR", str(tmp_path))
    out = apply_first_run_bootstrap(_settings())

    assert out.session_secret and out.session_secret != DEFAULT_SESSION_SECRET
    assert out.ui_admin_password
    # The generated login is announced once so the operator can read it from the logs.
    assert out.ui_admin_password in capsys.readouterr().err

    state = tmp_path / "bootstrap.json"
    assert state.exists()
    # Secrets must not be world/group readable on a shared home box.
    assert stat.S_IMODE(state.stat().st_mode) == 0o600


def test_reuses_persisted_across_restart(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BFF_STATE_DIR", str(tmp_path))
    first = apply_first_run_bootstrap(_settings())
    capsys.readouterr()  # drain the first-run banner

    second = apply_first_run_bootstrap(_settings())
    assert second.session_secret == first.session_secret
    assert second.ui_admin_password == first.ui_admin_password
    # No new credential generated → nothing announced on the restart.
    assert first.ui_admin_password not in capsys.readouterr().err


def test_env_override_wins_and_is_not_persisted(monkeypatch, tmp_path):
    """An operator who supplies every secret gets nothing written to their volume.

    The audit keys are part of "every secret" since ADR-0013 §9/§10 — supplying only the
    session secret and password would leave two to generate, which is what the sibling
    test below covers.
    """
    monkeypatch.setenv("BFF_STATE_DIR", str(tmp_path))
    out = apply_first_run_bootstrap(
        _settings(
            session_secret="operator-secret",
            ui_admin_password="operator-pw",
            audit_content_key=Fernet.generate_key().decode(),
            audit_pseudonym_key="operator-pseudonym-key",
        )
    )
    assert out.session_secret == "operator-secret"
    assert out.ui_admin_password == "operator-pw"
    # Nothing was generated, so no state file is written.
    assert not (tmp_path / "bootstrap.json").exists()


def test_audit_keys_are_generated_and_stable_across_restarts(monkeypatch, tmp_path):
    """A home box gets a shreddable, attributable audit from its FIRST record.

    Neither key can be introduced retroactively: records already written in the clear
    stay in the clear, and a hash chain cannot be re-keyed. So bootstrap generates both
    rather than leaving the operator to discover them in the documentation later.
    """
    monkeypatch.setenv("BFF_STATE_DIR", str(tmp_path))
    first = apply_first_run_bootstrap(_settings())
    assert first.audit_content_key and first.audit_pseudonym_key
    Fernet(first.audit_content_key.encode())  # a usable key, not just a string
    # And the chain gets somewhere durable to live, so it re-seeds instead of resetting.
    assert first.audit_path.endswith("audit.log")

    second = apply_first_run_bootstrap(_settings())
    assert second.audit_content_key == first.audit_content_key
    assert second.audit_pseudonym_key == first.audit_pseudonym_key


def test_env_password_but_generated_session_secret(monkeypatch, tmp_path):
    """Operator pins the password but not the secret → generate + persist only the secret."""
    monkeypatch.setenv("BFF_STATE_DIR", str(tmp_path))
    out = apply_first_run_bootstrap(_settings(ui_admin_password="operator-pw"))
    assert out.ui_admin_password == "operator-pw"
    assert out.session_secret and out.session_secret != DEFAULT_SESSION_SECRET

    import json

    stored = json.loads((tmp_path / "bootstrap.json").read_text())
    assert "session_secret" in stored and "admin_password" not in stored


# --- _secret: GATEWAY_API_TOKEN / *_FILE fallback (shared gateway key) --------


def test_secret_prefers_env_over_file(monkeypatch, tmp_path):
    f = tmp_path / "key"
    f.write_text("from-file")
    monkeypatch.setenv("GATEWAY_API_TOKEN", "from-env")
    monkeypatch.setenv("GATEWAY_TOKEN_FILE", str(f))
    assert _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE") == "from-env"


def test_secret_reads_file_when_env_empty(monkeypatch, tmp_path):
    f = tmp_path / "key"
    f.write_text("  from-file\n")  # surrounding whitespace is stripped
    monkeypatch.delenv("GATEWAY_API_TOKEN", raising=False)
    monkeypatch.setenv("GATEWAY_TOKEN_FILE", str(f))
    assert _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE") == "from-file"


def test_secret_empty_when_neither_set(monkeypatch):
    monkeypatch.delenv("GATEWAY_API_TOKEN", raising=False)
    monkeypatch.delenv("GATEWAY_TOKEN_FILE", raising=False)
    assert _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE") == ""


def test_secret_missing_file_is_empty(monkeypatch, tmp_path):
    monkeypatch.delenv("GATEWAY_API_TOKEN", raising=False)
    monkeypatch.setenv("GATEWAY_TOKEN_FILE", str(tmp_path / "does-not-exist"))
    assert _secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE") == ""
