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


def client_ip(request: Request, *, trusted_hops: int) -> str:
    """The caller's IP for throttling, counted back from the *right* of X-Forwarded-For.

    ``trusted_hops`` is how many reverse proxies sit in front of this BFF. 0 (the default)
    ignores the header entirely and uses the direct peer.

    **Why from the right.** A proxy appends; it does not replace. So a client that sends
    its own ``X-Forwarded-For: 1.2.3.4`` arrives at the app as ``1.2.3.4, <real client>``
    — the left-most entry is whatever the caller made up, and the right-most is the only
    one a trusted proxy actually observed. Reading from the left is therefore not a weaker
    heuristic but an inversion: it hands every caller a free, per-request identity to
    throttle under, which is worse than not trusting the header at all. With one proxy in
    front, ``trusted_hops=1`` yields the address nginx saw, spoofed prefix or not.

    A chain shorter than configured means the request did not traverse the proxies it was
    supposed to — someone reached the pod directly. That falls back to the peer address,
    which cannot be forged, rather than to an entry the caller may have authored.
    """
    peer = request.client.host if request.client else "unknown"
    if trusted_hops <= 0:
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    idx = len(hops) - trusted_hops
    return hops[idx] if 0 <= idx < len(hops) else peer
