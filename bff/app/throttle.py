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

import ipaddress
import time
from collections import OrderedDict, deque
from typing import Optional, Sequence, Union

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


_IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_trusted_proxy_cidrs(values: Sequence[str]) -> list[_IPNetwork]:
    """Parse ``TRUSTED_PROXY_CIDRS`` into networks, raising on anything invalid.

    A bare address is accepted as a single-host range (``10.0.0.5`` -> ``10.0.0.5/32``) so an
    operator naming one ingress IP need not write the mask. Invalid entries raise rather than
    being skipped: a typo'd CIDR silently dropped from the trust set is exactly the quiet
    mis-config that re-opens the hole it exists to close.

    Deliberately the same shape as the gateway's ``ratelimit.parse_trusted_proxy_cidrs`` --
    one concept, one spelling across both halves of the system.
    """
    nets: list[_IPNetwork] = []
    for raw in values:
        text = str(raw).strip()
        if not text:
            continue
        # strict=False so "10.0.0.5/24" reads as its containing network rather than being
        # rejected for having host bits set.
        nets.append(ipaddress.ip_network(text, strict=False))
    return nets


def _parse_ip(text: str):
    """An address from a header entry or peer, or None if it is not one.

    Strips an IPv6 scope id, then unwraps an IPv4-mapped IPv6 address to the IPv4 it really
    is, so ``::ffff:10.0.0.5`` matches a ``10.0.0.0/8`` trust entry.
    """
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _is_trusted(text: str, nets: Sequence[_IPNetwork]) -> bool:
    ip = _parse_ip(text)
    if ip is None:
        return False
    return any(ip.version == net.version and ip in net for net in nets)


def client_ip(request: Request, *, trusted_cidrs: Sequence[_IPNetwork]) -> str:
    """The caller's IP for throttling, resolved from the end of the chain we can vouch for.

    Behind an ingress ``request.client.host`` is the controller, so every user shares one
    throttle bucket and the real client has to come from ``X-Forwarded-For``. That header is
    a list the caller can prepend to, so *which* entry is believed is the whole question.

    **This replaces a hop count, and the difference is not cosmetic.** Counting a fixed
    number of entries back from the right closes the spoofed-prefix case but still trusts the
    header of whoever is connected -- so a caller who reaches this pod *directly*, skipping
    the proxy entirely, supplies their own bucket key and gets a fresh one per request. The
    walk below starts at the TCP peer and pops entries off the right only while each hop is
    infrastructure we own, so an attacker who skips the proxy fails at the very first step:
    their peer is untrusted, the walk never starts, and their header is never read. One
    behind the proxy gets only the entry the proxy itself appended -- their real address --
    and whatever they prepended sits to the left of it and is never reached.

    Falls back to the peer when there is no header, when every hop is trusted (no client to
    identify), or when the resolved hop is not a valid address -- a junk entry must never
    become an arbitrary, attacker-chosen bucket key.

    An empty trust set ignores the header entirely. That is the safe direction: it
    over-counts a shared proxy address and never trusts a caller-supplied one.

    This is the gateway's ``ratelimit.client_ip_key_func`` logic, deliberately mirrored. The
    BFF originally grew its own weaker answer to a problem this system had already solved.
    """
    peer = request.client.host if request.client else "unknown"
    if not trusted_cidrs:
        return peer
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer

    entries = [e.strip() for e in xff.split(",") if e.strip()]
    hop = peer
    # Pop from the right while the hop we just came from is infrastructure we own.
    while entries and _is_trusted(hop, trusted_cidrs):
        hop = entries.pop()
    if _is_trusted(hop, trusted_cidrs) or _parse_ip(hop) is None:
        return peer
    return hop
