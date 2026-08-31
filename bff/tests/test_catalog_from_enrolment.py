# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""ADR-0024 §10 — a tenant console learns its catalog configuration from its own enrolment.

Enrolling used to be necessary but not sufficient: the handshake put the tenant's catalog
address and credential on its gateway, and someone still had to copy them into a deployment and
restart it. This closes that.

The properties that matter, and why each is a test rather than a comment:

* **explicit configuration still wins.** Installing a resolver must not change how an
  already-configured deployment behaves — an env var that silently does nothing is worse than
  one that is merely redundant;
* **resolution is lazy and repeatable.** A console whose gateway is down at boot must not be
  permanently catalog-less, and a tenant that enrols an hour later must not need a restart;
* **one call, not one per request**, and a cooldown, so an un-enrolled tenant is not asking its
  gateway on every page load;
* **a provider console never does this at all** — it holds the privileged credential and is the
  party others enrol *with*.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.catalog_client import RESOLVE_COOLDOWN_SECONDS, CatalogClient, CatalogUnavailable
from app.catalog_enrolment import CATALOG_CONFIGURATION_PATH, gateway_resolver

CATALOG_URL = "http://catalog.internal"
CREDENTIAL = "cat_from_enrolment"


class _Settings:
    """Only the attributes CatalogClient reads — the same shape `gateway_pool` uses for
    GatewayClient, and deliberately not a real Settings, which also carries UI passwords and a
    session secret that have nothing to do with one outbound connection."""

    def __init__(self, *, url: str = "", token: str = "", tenant_id: str = "t-1", provider: bool = False):
        self.catalog_service_url = url
        self.catalog_api_token = token
        self.tenant_id = tenant_id
        self.provider_oidc_enabled = provider


class _Gateway:
    """Answers the one route the resolver calls, and counts the asking."""

    def __init__(self, *, status: int = 200, credential: str = CREDENTIAL, url: str = CATALOG_URL):
        self.calls: list[str] = []
        self.status = status
        self.credential = credential
        self.url = url

    async def get(self, path: str, *, bearer=None):
        self.calls.append(path)
        # A real await point, so a burst genuinely interleaves. Without one every "async" call
        # here runs to completion before yielding, and the concurrency test below would pass
        # against a client that had no lock at all — a guard that cannot fail.
        await asyncio.sleep(0)
        if self.status != 200:
            return httpx.Response(self.status, json={"detail": "no live enrolment"})
        return httpx.Response(
            200,
            json={"catalog_url": self.url, "catalog_credential": self.credential, "enrolment_id": "e-1"},
        )


def _catalog(settings: _Settings, gateway: _Gateway | None) -> CatalogClient:
    return CatalogClient(settings, resolver=gateway_resolver(gateway) if gateway else None)


def _transport(client: CatalogClient, handler) -> None:
    """Swap the live client's transport so a request goes nowhere real. Done after
    construction on purpose: the point is to observe the base_url and Authorization the client
    ends up with, which is what `_adopt` changes."""
    client._client._transport = httpx.MockTransport(handler)


def _echo(seen: list[httpx.Request], status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json={"device_types": []})

    return handler


# --- explicit configuration wins -------------------------------------------------------------


async def test_env_configuration_is_never_overridden_by_an_enrolment():
    """An operator who set CATALOG_API_TOKEN deliberately must not have it silently replaced by
    a value fetched from somewhere else — and every deployment that worked before this change
    must behave identically after it."""
    gateway = _Gateway()
    client = _catalog(_Settings(url="http://env.catalog", token="cat_from_env"), gateway)
    seen: list[httpx.Request] = []
    _transport(client, _echo(seen))

    await client.request("GET", "/device-types")

    assert gateway.calls == [], "an already-configured console must not ask its gateway anything"
    assert seen[0].headers["authorization"] == "Bearer cat_from_env"
    assert str(seen[0].url).startswith("http://env.catalog")


# --- learning it from the enrolment ------------------------------------------------------------


async def test_an_unconfigured_console_learns_the_address_and_credential():
    gateway = _Gateway()
    client = _catalog(_Settings(), gateway)
    seen: list[httpx.Request] = []
    _transport(client, _echo(seen))

    await client.request("GET", "/device-types")

    assert gateway.calls == [CATALOG_CONFIGURATION_PATH]
    assert seen[0].headers["authorization"] == f"Bearer {CREDENTIAL}"
    assert str(seen[0].url).startswith(CATALOG_URL)
    assert client.configured


async def test_the_tenant_declaration_is_not_taken_from_the_credential_we_were_handed():
    """ADR-0020 §7b: the declaration is this deployment's own identity. A credential arriving
    with the power to change what tenant this console claims to be would defeat the check it
    exists to pass."""
    client = _catalog(_Settings(tenant_id="t-mine"), _Gateway())
    seen: list[httpx.Request] = []
    _transport(client, _echo(seen))

    await client.request("GET", "/device-types")

    assert seen[0].headers["x-catalog-tenant"] == "t-mine"


async def test_an_unenrolled_tenant_stays_a_named_condition_rather_than_an_error():
    """404 is the ordinary state of a tenant that has not enrolled yet, not a fault. It has to
    read as "no catalog here", which every route already renders — the same posture ADR-0020 §7
    takes towards a catalog outage, one step earlier."""
    client = _catalog(_Settings(), _Gateway(status=404))
    with pytest.raises(CatalogUnavailable) as caught:
        await client.request("GET", "/device-types")
    assert "enrolment" in str(caught.value)
    assert not client.configured


async def test_a_gateway_that_raises_does_not_take_the_console_down():
    class _Broken:
        calls: list[str] = []

        async def get(self, path, *, bearer=None):
            raise httpx.ConnectError("no route to host")

    client = CatalogClient(_Settings(), resolver=gateway_resolver(_Broken()))
    with pytest.raises(CatalogUnavailable):
        await client.request("GET", "/device-types")


async def test_a_partial_answer_is_not_adopted():
    """An address with no credential, or the reverse, would configure a client that cannot
    authenticate — and it would then stop asking, because it would believe itself configured."""
    client = _catalog(_Settings(), _Gateway(credential=""))
    with pytest.raises(CatalogUnavailable):
        await client.request("GET", "/device-types")
    assert not client.configured


# --- how often it asks ------------------------------------------------------------------------


async def test_a_burst_of_requests_produces_one_gateway_call():
    """A cold console serving a page that makes several catalog calls at once must not ask its
    gateway several times for the same answer."""
    gateway = _Gateway()
    client = _catalog(_Settings(), gateway)
    _transport(client, _echo([]))

    await asyncio.gather(*(client.request("GET", "/device-types") for _ in range(5)))

    assert gateway.calls == [CATALOG_CONFIGURATION_PATH]


async def test_an_unenrolled_console_is_not_asking_on_every_request():
    gateway = _Gateway(status=404)
    client = _catalog(_Settings(), gateway)

    for _ in range(4):
        with pytest.raises(CatalogUnavailable):
            await client.request("GET", "/device-types")

    assert gateway.calls == [CATALOG_CONFIGURATION_PATH], "the cooldown is what keeps this off the hot path"


async def test_it_asks_again_once_the_cooldown_has_passed(monkeypatch):
    """Lazy and *repeatable*: a tenant that enrols an hour after its console started must not
    need a restart to notice."""
    gateway = _Gateway(status=404)
    client = _catalog(_Settings(), gateway)
    with pytest.raises(CatalogUnavailable):
        await client.request("GET", "/device-types")

    client._resolve_attempted_at -= RESOLVE_COOLDOWN_SECONDS + 1
    gateway.status = 200
    _transport(client, _echo([]))
    await client.request("GET", "/device-types")

    assert len(gateway.calls) == 2
    assert client.configured


# --- a credential that stops working ------------------------------------------------------------


async def test_a_401_re_resolves_and_retries_with_the_new_credential():
    """What a revoked-and-re-enrolled relationship looks like from here. Without this the
    console keeps presenting a dead credential until someone restarts it."""
    gateway = _Gateway()
    client = _catalog(_Settings(), gateway)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        # The first credential is dead; the one the gateway hands over next is not.
        if request.headers["authorization"] == f"Bearer {CREDENTIAL}":
            return httpx.Response(401, json={"detail": "unknown credential"})
        return httpx.Response(200, json={"device_types": []})

    _transport(client, handler)
    await client.request("GET", "/device-types")  # resolves, gets the dead one
    gateway.credential = "cat_reissued"

    resp = await client.request("GET", "/device-types")

    assert resp.status_code == 200
    assert seen[-1].headers["authorization"] == "Bearer cat_reissued"


async def test_a_401_that_learns_nothing_new_is_not_retried_in_a_loop():
    """The credential is dead and re-resolving returns the same one — a genuinely revoked
    tenant. One extra call, then the 401 is returned as it stands."""
    gateway = _Gateway()
    client = _catalog(_Settings(), gateway)
    seen: list[httpx.Request] = []
    _transport(client, _echo(seen, status=401))

    resp = await client.request("GET", "/device-types")

    assert resp.status_code == 401
    assert len(seen) == 1, "re-sending an identical credential would only produce the same 401"


async def test_a_401_on_an_env_configured_console_is_not_re_resolved():
    """There is no resolver installed, so nothing to ask — and the 401 is the operator's answer:
    the credential in this deployment's configuration is not accepted."""
    client = _catalog(_Settings(url="http://env.catalog", token="cat_from_env"), None)
    seen: list[httpx.Request] = []
    _transport(client, _echo(seen, status=401))

    assert (await client.request("GET", "/device-types")).status_code == 401
    assert len(seen) == 1


# --- the plane that must never do this ----------------------------------------------------------


def test_a_provider_console_installs_no_resolver_at_all(monkeypatch, tmp_path):
    """A provider BFF holds the privileged catalog credential from its own configuration and is
    the party others enrol *with* — it has no enrolment of its own to learn from. Asking a
    gateway for a credential would be the misdelivery ADR-0020 §7b exists to catch, arriving by
    the console's own hand rather than an operator's typo.

    Asserted on the constructed app rather than by reading `main.py`, because the thing that
    must be true is that the wiring produced no resolver — not that a line of code says so.
    """
    import os

    os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
    os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
    from fastapi.testclient import TestClient

    from app.main import create_app

    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "true")
    monkeypatch.setenv("PROVIDER_OIDC_ISSUER", "https://provider.idp.invalid")
    monkeypatch.setenv("PROVIDER_OIDC_CLIENT_ID", "provider-console")
    monkeypatch.setenv("PROVIDER_OIDC_REDIRECT_URL", "https://console.example.com/auth/provider/callback")
    monkeypatch.setenv("PROVIDER_GROUP_SCOPES", '{"provider-support": "provider:admin"}')
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))
    monkeypatch.delenv("CATALOG_SERVICE_URL", raising=False)
    monkeypatch.delenv("CATALOG_API_TOKEN", raising=False)

    app = create_app()
    with TestClient(app):
        assert app.state.catalog._resolver is None


def test_a_tenant_console_does_install_one(monkeypatch, tmp_path):
    """The other half of the pair — a guard that only ever asserted "not on the provider" would
    pass just as well if the feature were wired nowhere."""
    import os

    os.environ.setdefault("UI_ADMIN_PASSWORD", "admin-pw")
    os.environ.setdefault("UI_VIEWER_PASSWORD", "viewer-pw")
    from fastapi.testclient import TestClient

    from app.main import create_app

    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("PROVIDER_OIDC_ENABLED", "false")
    monkeypatch.setenv("AUDIT_PATH", str(tmp_path / "audit.log"))

    app = create_app()
    with TestClient(app):
        assert app.state.catalog._resolver is not None


# --- a stale address must not outlive the enrolment that supplied it -------------------------
#
# Found in the browser, after two other fixes had already made the data correct. A tenant
# console had adopted the provider's in-cluster catalog address, the enrolment was then
# repaired to carry the right one, and the console kept answering
# `[Errno -3] Temporary failure in name resolution` — because `_resolve` returns early while
# `_configured` is true and only a 401 forced it. The address survived for the life of the pod.
#
# "The catalog is unreachable at the address I remember" is as much a sign the relationship
# changed as "my credential was rejected", so it triggers the same re-resolve.


class _MovingGateway:
    """A gateway whose enrolment is repaired between calls — a provider that fixed the address
    it hands out, which is exactly the situation the retry exists for."""

    def __init__(self, urls: list[str]):
        self._urls = list(urls)
        self.calls = 0

    async def get(self, path: str, *, bearer=None):
        self.calls += 1
        url = self._urls[min(self.calls, len(self._urls)) - 1]
        await asyncio.sleep(0)
        return httpx.Response(200, json={"catalog_url": url, "catalog_credential": CREDENTIAL, "enrolment_id": "e-1"})


@pytest.mark.asyncio
async def test_a_transport_failure_re_resolves_and_retries():
    gateway = _MovingGateway(["http://old.invalid", "http://new.example"])
    client = _catalog(_Settings(), gateway)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if "old.invalid" in str(request.url):
            raise httpx.ConnectError("[Errno -3] Temporary failure in name resolution")
        return httpx.Response(200, json={"device_types": []})

    _transport(client, handler)
    resp = await client.request("GET", "/tenants/t-1/assignments")

    assert resp.status_code == 200, "the corrected address was never tried"
    assert any("old.invalid" in u for u in seen) and any("new.example" in u for u in seen)


@pytest.mark.asyncio
async def test_a_transport_failure_that_learns_nothing_new_reports_the_original_error():
    """No retry when re-resolving returns the same address: a second attempt fails identically,
    and reporting the retry's error would only restate the first."""
    gateway = _MovingGateway(["http://same.invalid"])
    client = _catalog(_Settings(), gateway)
    attempts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(str(request.url))
        raise httpx.ConnectError("[Errno -3] Temporary failure in name resolution")

    _transport(client, handler)
    with pytest.raises(CatalogUnavailable, match="Temporary failure in name resolution"):
        await client.request("GET", "/tenants/t-1/assignments")

    assert len(attempts) == 1, "retried against an address that had not changed"
