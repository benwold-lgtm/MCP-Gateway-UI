# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""First-run bootstrap for the LITE / home deployment.

A home user shouldn't have to hand-pick a session secret or an admin password before
the UI will run. When ``BFF_STATE_DIR`` is set (the lite compose points it at a mounted
volume), this module fills in whatever secret the operator did NOT provide via the
environment: it generates a strong value, persists it under the state dir so it survives
restarts, and prints the login once on the run that created it.

Opt-in by design. With ``BFF_STATE_DIR`` unset (the default, and every enterprise
deploy) this is a no-op — nothing is generated, nothing is written to disk, and the
existing env-driven configuration and the ``COOKIE_SECURE`` fail-closed check in
``create_app`` behave exactly as before.

Precedence for each secret: an explicit environment value always wins; otherwise a
previously persisted value is reused; otherwise a fresh one is generated and persisted.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

from .config import DEFAULT_SESSION_SECRET, Settings

STATE_FILENAME = "bootstrap.json"


def apply_first_run_bootstrap(settings: Settings) -> Settings:
    """Return settings with any missing lite secrets filled in from disk or freshly
    generated. No-op (returns the input unchanged) unless ``BFF_STATE_DIR`` is set."""
    state_dir = os.getenv("BFF_STATE_DIR", "").strip()
    if not state_dir:
        return settings

    try:
        return _bootstrap(settings, Path(state_dir) / STATE_FILENAME)
    except OSError as exc:
        # A home box with an unwritable state dir/volume shouldn't fail to boot — fall back
        # to whatever the environment already provides. Covers a failure at any point in the
        # flow (mkdir, load, *or* save — a volume can be readable but not writable).
        print(f"[bootstrap] state dir {state_dir!r} unavailable ({exc}); skipping", flush=True)
        return settings


def _bootstrap(settings: Settings, path: Path) -> Settings:
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = _load(path)

    # str values, but typed Any so dataclasses.replace(**updates) type-checks against the
    # mixed-type Settings fields.
    updates: dict[str, Any] = {}
    to_persist = dict(stored)
    generated_password: str | None = None

    # Session secret: env override (a real, non-default value) wins; else reuse persisted;
    # else generate. Persisting it keeps sessions valid across container restarts.
    if settings.session_secret and settings.session_secret != DEFAULT_SESSION_SECRET:
        pass  # operator supplied one via SESSION_SECRET
    elif stored.get("session_secret"):
        updates["session_secret"] = stored["session_secret"]
    else:
        value = secrets.token_hex(32)
        updates["session_secret"] = value
        to_persist["session_secret"] = value

    # Admin password: env override wins; else reuse persisted; else generate and announce.
    if settings.ui_admin_password:
        pass  # operator supplied one via UI_ADMIN_PASSWORD
    elif stored.get("admin_password"):
        updates["ui_admin_password"] = stored["admin_password"]
    else:
        generated_password = secrets.token_urlsafe(12)
        updates["ui_admin_password"] = generated_password
        to_persist["admin_password"] = generated_password

    if to_persist != stored:
        _save(path, to_persist)

    if generated_password is not None:
        _announce_login(generated_password, path)

    return dataclasses.replace(settings, **updates) if updates else settings


def _load(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}


def _save(path: Path, data: dict[str, str]) -> None:
    # Write private (0600) before anyone can read it: create with restrictive perms, then
    # write. Secrets on a shared home box should never be world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, json.dumps(data, indent=2).encode())
    finally:
        os.close(fd)


def _announce_login(password: str, path: Path) -> None:
    banner = (
        "\n"
        "============================================================\n"
        " Device MCP Gateway (lite) — first-run admin login created\n"
        "------------------------------------------------------------\n"
        "   URL:      http://<this-host>:8080\n"
        "   Username: admin\n"
        f"   Password: {password}\n"
        "------------------------------------------------------------\n"
        f" Saved to {path} — delete that file to generate a new one.\n"
        " Set UI_ADMIN_PASSWORD to choose your own instead.\n"
        "============================================================\n"
    )
    print(banner, file=sys.stderr, flush=True)
