# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Which address the login throttle counts against, behind a reverse proxy.

Behind an ingress the direct peer is the *controller's* address for every user, so the
throttle degrades into a single shared bucket: one person fumbling a password throttles
everyone, including the break-glass login whose whole purpose is to work when other paths
are broken. Reading `X-Forwarded-For` is the fix — but only from the right-hand end.

A proxy appends to the header, it does not replace it. So a caller who sends their own
`X-Forwarded-For` arrives as `<their text>, <address the proxy saw>`. Trusting the
left-most entry hands every caller a free per-request identity and makes the throttle
weaker than not reading the header at all. These tests pin that direction.
"""

import pytest

from app.config import _trusted_proxy_hops
from app.throttle import client_ip


class _Req:
    """Minimal stand-in: `client_ip` only reads `.headers` and `.client.host`."""

    def __init__(self, peer: str | None, xff: str | None = None):
        self.headers = {"x-forwarded-for": xff} if xff is not None else {}
        self.client = type("C", (), {"host": peer})() if peer else None


# --- no proxy in front ---------------------------------------------------------


def test_zero_hops_ignores_the_header_entirely():
    r = _Req("10.0.0.9", "1.2.3.4")
    assert client_ip(r, trusted_hops=0) == "10.0.0.9"


def test_missing_client_is_named_not_guessed():
    assert client_ip(_Req(None), trusted_hops=0) == "unknown"


# --- one proxy in front (the shipped ingress topology) -------------------------


def test_one_hop_reads_what_the_proxy_saw():
    r = _Req("10.244.0.125", "203.0.113.7")
    assert client_ip(r, trusted_hops=1) == "203.0.113.7"


def test_a_spoofed_prefix_does_not_win():
    """The regression this whole change exists for. The caller invents a left-most entry;
    the proxy appends the address it actually observed. Counting from the right returns
    the observed one, so the throttle still tracks the real caller."""
    r = _Req("10.244.0.125", "9.9.9.9, 203.0.113.7")
    assert client_ip(r, trusted_hops=1) == "203.0.113.7"


def test_a_long_invented_chain_does_not_win_either():
    """Padding the header with extra hops is the obvious follow-up attempt: it shifts the
    left-most entry but never the right-most."""
    r = _Req("10.244.0.125", "1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.7")
    assert client_ip(r, trusted_hops=1) == "203.0.113.7"


def test_two_hops_counts_back_two():
    r = _Req("10.244.0.125", "203.0.113.7, 172.16.0.1")
    assert client_ip(r, trusted_hops=2) == "203.0.113.7"


# --- the chain is not what was configured --------------------------------------


@pytest.mark.parametrize("xff", [None, "", "   ", ","])
def test_no_usable_header_falls_back_to_the_peer(xff):
    """Someone reached the pod directly, bypassing the proxy. The peer address cannot be
    forged, so it is the safe answer -- never an entry the caller may have authored."""
    assert client_ip(_Req("10.0.0.9", xff), trusted_hops=1) == "10.0.0.9"


def test_a_chain_shorter_than_configured_falls_back_to_the_peer():
    """Two hops configured, one present: the request did not traverse the proxies it was
    supposed to. Returning hops[0] here would be exactly the spoofable read this change
    removes, so it must return the peer instead."""
    assert client_ip(_Req("10.0.0.9", "9.9.9.9"), trusted_hops=2) == "10.0.0.9"


# --- how the setting is read ---------------------------------------------------


def test_hops_default_to_zero(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.delenv("TRUST_FORWARDED_FOR", raising=False)
    assert _trusted_proxy_hops() == 0


def test_the_old_boolean_still_means_one_hop(monkeypatch):
    """A deployment carrying TRUST_FORWARDED_FOR named a topology, and the topology has
    not changed -- only which entry gets believed. Ignoring the old flag would silently
    return that deployment to one shared throttle bucket."""
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.setenv("TRUST_FORWARDED_FOR", "true")
    assert _trusted_proxy_hops() == 1


def test_the_explicit_count_wins_over_the_old_flag(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    monkeypatch.setenv("TRUST_FORWARDED_FOR", "true")
    assert _trusted_proxy_hops() == 2


@pytest.mark.parametrize("raw", ["nonsense", "-1", "1.5", ""])
def test_an_unusable_count_reads_as_no_proxy(monkeypatch, raw):
    """The safe direction: 0 only ever over-counts a shared proxy address, and never
    trusts a caller-supplied one."""
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", raw)
    monkeypatch.delenv("TRUST_FORWARDED_FOR", raising=False)
    assert _trusted_proxy_hops() == 0
