# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""The correlation id that spans console click → gateway → device (ADR-0026).

The gateway accepts permanently that a device sees one service identity per device, never
the caller, and leans the whole of "who really did this" on being able to join its audit
record to the device's own log. The join key is the request id, and the gateway already
carries it from its own front door all the way onto the wire.

This module supplies the hop before that one. A human's action starts *here*, in the
console — so if the BFF minted nothing and forwarded nothing, the chain would be broken at
its first link and the id would only ever span the gateway's half of a journey that began
in a browser. The BFF therefore mints the id when the browser does not supply one, records
it on its own audit row, returns it to the browser, and puts it on every outbound hop:
the tenant gateway, another tenant's gateway through the relay pool, and the catalog.

Deliberately the same three properties as the gateway's ``core/correlation.py``:

  * **One seam per client.** ``with_correlation_hook`` is installed where the long-lived
    ``httpx.AsyncClient`` is built, not at each call site.
  * **Assigned, not defaulted.** The hook overwrites, so no caller-supplied header can
    choose the id that will identify it.
  * **Never invented at egress.** No request in scope means no header, rather than an id
    that looks like a correlation id and joins to nothing. The front-door middleware is
    the only place one is minted.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

import httpx

CORRELATION_HEADER = "X-Request-Id"

# "-" is what a missing id looks like on the gateway's worker stream; treat any of these as
# absent rather than stamping a literal placeholder onto a request.
_ABSENT = frozenset({"", "-", "none", "None"})

_current_request_id: ContextVar[str] = ContextVar("bff_request_id", default="")


def current_request_id() -> str:
    """The request id in scope, or ``""`` when there is none."""
    rid = _current_request_id.get()
    return "" if rid in _ABSENT else rid


@contextmanager
def use_request_id(rid: str | None) -> Iterator[str]:
    """Bind ``rid`` for the duration of the block, restoring the previous value after."""
    token = _current_request_id.set(rid or "")
    try:
        yield current_request_id()
    finally:
        _current_request_id.reset(token)


async def stamp_correlation(request: httpx.Request) -> None:
    """httpx request hook: put the in-scope request id on the outbound hop."""
    rid = current_request_id()
    if rid:
        request.headers[CORRELATION_HEADER] = rid


def with_correlation_hook(event_hooks: Any = None) -> dict[str, list[Any]]:
    """Merge :func:`stamp_correlation` into a caller's ``event_hooks`` mapping."""
    hooks: dict[str, list[Any]] = {k: list(v) for k, v in (event_hooks or {}).items()}
    hooks.setdefault("request", []).append(stamp_correlation)
    return hooks
