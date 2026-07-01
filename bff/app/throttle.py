# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""In-process login throttle for the break-glass password (review #3).

The local admin/viewer password is a high-value target: constant-time comparison
(``resolve_role``) stops a timing side-channel but not brute force. After
``max_failures`` failed attempts from one client IP within ``window`` seconds, further
attempts are refused with ``429`` (and a ``Retry-After``) until the window rolls off; a
successful login clears that IP's failures.

This is deliberately in-process (the BFF has no Redis dependency). With multiple replicas
each enforces independently, so the effective rate is ``replicas × max_failures`` per
window — still a hard bound on brute force, just not a globally shared counter. Memory is
bounded by evicting the oldest tracked IP past ``max_tracked``.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from typing import Optional

from fastapi import Request


class LoginThrottle:
    def __init__(self, *, max_failures: int = 5, window: int = 60, max_tracked: int = 10_000) -> None:
        self.max_failures = max_failures
        self.window = window
        self._max_tracked = max_tracked
        # ip -> timestamps (monotonic) of recent failures, most-recently-touched last.
        self._fails: "OrderedDict[str, deque[float]]" = OrderedDict()

    def _prune(self, ip: str, now: float) -> Optional[deque]:
        dq = self._fails.get(ip)
        if dq is None:
            return None
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            self._fails.pop(ip, None)
            return None
        return dq

    def retry_after(self, ip: str) -> int:
        """Seconds the caller must wait if ``ip`` is currently locked out, else 0."""
        dq = self._prune(ip, time.monotonic())
        if dq is not None and len(dq) >= self.max_failures:
            # The lock lifts when the oldest failure in the window ages out.
            return max(1, int(self.window - (time.monotonic() - dq[0])) + 1)
        return 0

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        dq = self._fails.get(ip)
        if dq is None:
            if len(self._fails) >= self._max_tracked:
                self._fails.popitem(last=False)  # evict the least-recently-touched IP
            dq = self._fails[ip] = deque()
        self._fails.move_to_end(ip)
        dq.append(now)

    def record_success(self, ip: str) -> None:
        self._fails.pop(ip, None)


def client_ip(request: Request, *, trust_forwarded: bool) -> str:
    """The caller's IP for throttling. Uses the direct peer by default; only reads the
    left-most X-Forwarded-For hop when ``trust_forwarded`` is set (the BFF is behind a
    trusted proxy that appends it) — otherwise a client could spoof the header to dodge
    the throttle."""
    if trust_forwarded:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
