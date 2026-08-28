# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Which address the login throttle counts against, behind a reverse proxy.

Behind an ingress the direct peer is the controller's address for every user, so the
throttle degrades into a single shared bucket: one person fumbling a password throttles
everyone, including the break-glass login whose whole purpose is to work when other paths
are broken. Reading `X-Forwarded-For` is the fix -- but the header is a list the caller can
prepend to, so *which* entry gets believed is the whole question.

These tests pin the walk: start at the TCP peer, pop entries off the RIGHT only while each
hop is infrastructure we own. Two attacks have to fail, and only one of them is defeated by
reading right-to-left:

  * a caller who prepends junk while coming *through* the proxy, and
  * a caller who skips the proxy and connects to the pod directly.

The second is why this is a trust set and not a hop count. A count says how far to walk but
not whether the request arrived the way it was supposed to.
"""

import ipaddress

import pytest

from app.config import ProxyTrustError, _trusted_proxy_cidrs
from app.throttle import client_ip, parse_trusted_proxy_cidrs

TRUSTED = parse_trusted_proxy_cidrs(["10.244.0.0/16"])


class _Req:
    """Minimal stand-in: `client_ip` only reads `.headers` and `.client.host`."""

    def __init__(self, peer: str | None, xff: str | None = None):
        self.headers = {"x-forwarded-for": xff} if xff is not None else {}
        self.client = type("C", (), {"host": peer})() if peer else None


# --- no trust set: the header is not read at all -------------------------------


def test_empty_trust_set_ignores_the_header():
    assert client_ip(_Req("10.244.0.125", "1.2.3.4"), trusted_cidrs=[]) == "10.244.0.125"


def test_missing_client_is_named_not_guessed():
    assert client_ip(_Req(None), trusted_cidrs=[]) == "unknown"


# --- through the proxy ---------------------------------------------------------


def test_one_trusted_hop_reads_what_the_proxy_saw():
    assert client_ip(_Req("10.244.0.125", "203.0.113.7"), trusted_cidrs=TRUSTED) == "203.0.113.7"


def test_a_spoofed_prefix_does_not_win():
    """The caller invents a left-most entry; the proxy appends what it observed."""
    r = _Req("10.244.0.125", "9.9.9.9, 203.0.113.7")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "203.0.113.7"


def test_a_long_invented_chain_does_not_win_either():
    r = _Req("10.244.0.125", "1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.7")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "203.0.113.7"


def test_the_walk_crosses_every_trusted_hop():
    """Two of our own proxies chained: both are popped, the client is what remains."""
    r = _Req("10.244.0.1", "203.0.113.7, 10.244.0.9")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "203.0.113.7"


# --- skipping the proxy: the case a hop count cannot defend --------------------


def test_a_direct_connection_cannot_choose_its_own_bucket():
    """The regression this change exists for, and the one the previous hop-count
    implementation got wrong: it returned 1.2.3.4 here -- an attacker-chosen key, fresh on
    every request. The peer is not in the trust set, so the walk never starts."""
    r = _Req("203.0.113.9", "1.2.3.4")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "203.0.113.9"


def test_a_direct_connection_with_a_long_chain_still_cannot():
    r = _Req("203.0.113.9", "1.1.1.1, 2.2.2.2, 10.244.0.5")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "203.0.113.9"


# --- degenerate chains ---------------------------------------------------------


@pytest.mark.parametrize("xff", [None, "", "   ", ","])
def test_no_usable_header_falls_back_to_the_peer(xff):
    assert client_ip(_Req("10.244.0.125", xff), trusted_cidrs=TRUSTED) == "10.244.0.125"


def test_an_all_trusted_chain_identifies_no_client():
    """Every hop is ours, so there is no client entry left. The peer is the honest answer,
    not the last trusted hop dressed up as a client."""
    r = _Req("10.244.0.1", "10.244.0.5, 10.244.0.9")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "10.244.0.1"


def test_a_junk_entry_never_becomes_a_bucket_key():
    """An arbitrary -- and arbitrarily long -- attacker-chosen string must not key the
    throttle's memory-bounded map."""
    r = _Req("10.244.0.125", "not-an-ip")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "10.244.0.125"


def test_an_ipv4_mapped_ipv6_hop_matches_an_ipv4_trust_entry():
    r = _Req("::ffff:10.244.0.125", "203.0.113.7")
    assert client_ip(r, trusted_cidrs=TRUSTED) == "203.0.113.7"


# --- parsing the trust set -----------------------------------------------------


def test_a_bare_address_is_a_single_host_range():
    nets = parse_trusted_proxy_cidrs(["10.0.0.5"])
    assert nets == [ipaddress.ip_network("10.0.0.5/32")]


def test_host_bits_are_tolerated():
    assert parse_trusted_proxy_cidrs(["10.0.0.5/24"]) == [ipaddress.ip_network("10.0.0.0/24")]


def test_a_typo_raises_rather_than_being_skipped():
    """Silently dropping a bad entry shrinks the trust set, and a shrunken trust set fails
    open in the direction of ignoring the header -- which looks like it is working."""
    with pytest.raises(ValueError):
        parse_trusted_proxy_cidrs(["10.0.0.0/8", "not-a-cidr"])


# --- the settings that are recognised only to be refused -----------------------


def test_cidrs_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.244.0.0/16, 172.18.0.5")
    monkeypatch.delenv("TRUST_FORWARDED_FOR", raising=False)
    assert _trusted_proxy_cidrs() == ["10.244.0.0/16", "172.18.0.5"]


@pytest.mark.parametrize("legacy", ["TRUST_FORWARDED_FOR", "TRUSTED_PROXY_HOPS"])
def test_a_legacy_proxy_setting_is_refused_not_ignored(monkeypatch, legacy):
    """Ignoring it would be worse than refusing: the deployment boots, looks configured,
    and quietly returns every user to one shared throttle bucket."""
    monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.delenv("TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.setenv(legacy, "1")
    with pytest.raises(ProxyTrustError) as err:
        _trusted_proxy_cidrs()
    assert "TRUSTED_PROXY_CIDRS" in str(err.value), "the refusal must name the replacement"


@pytest.mark.parametrize("off", ["false", "0", "no", ""])
def test_a_legacy_setting_left_switched_off_is_not_refused(monkeypatch, off):
    """Only an *active* legacy setting is a mis-configuration. Refusing to boot over a
    leftover `TRUST_FORWARDED_FOR=false` would punish a deployment that is already correct."""
    monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.setenv("TRUST_FORWARDED_FOR", off)
    assert _trusted_proxy_cidrs() == []


def test_explicit_cidrs_win_over_a_legacy_setting(monkeypatch):
    """A deployment that has migrated must not be blocked by an env var nobody cleaned up."""
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.244.0.0/16")
    monkeypatch.setenv("TRUST_FORWARDED_FOR", "true")
    assert _trusted_proxy_cidrs() == ["10.244.0.0/16"]
