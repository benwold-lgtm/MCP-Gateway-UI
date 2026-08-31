# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""BFF settings, loaded from the environment.

The gateway admin token lives here on the server only — it is NEVER sent to the
browser. The browser holds an opaque signed session cookie; the BFF translates a
session into upstream calls authenticated with the gateway token.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# The session cookie carries only an opaque session id (content lives in the server-side
# store, app/sessions.py) plus the short-lived OIDC login transaction. The secret still
# matters: a known default lets an attacker mint cookies and tamper with the OIDC
# state/nonce/PKCE transaction (login CSRF). Booting with it under TLS is refused in
# main.create_app().
DEFAULT_SESSION_SECRET = "dev-insecure-change-me"


@dataclass(frozen=True)
class Settings:
    gateway_url: str
    gateway_api_prefix: str
    gateway_token: str
    ui_admin_password: str
    ui_viewer_password: str
    session_secret: str
    prometheus_url: str
    loki_url: str
    grafana_url: str = ""
    # Server-side session store (app/sessions.py). Default: in-process memory — right
    # for a single replica (lite/dev). Set SESSION_REDIS_URL when running >1 BFF
    # replica (the K8s overlay does) so any replica can resolve any session.
    session_redis_url: str = ""
    session_ttl_seconds: int = 28800  # 8 hours
    cors_origins: list[str] = field(default_factory=list)
    cookie_secure: bool = False
    # Recognised so it can be REFUSED — see `create_app`. There is no supported way to widen
    # the session cookie beyond the host that set it, and this exists so the attempt fails
    # loudly instead of being made at a reverse proxy where nothing can see it.
    cookie_domain: str = ""
    # Break-glass password login throttle (review #3): after login_max_failures failed
    # attempts from one client IP within login_window_seconds, further attempts get 429.
    login_max_failures: int = 5
    login_window_seconds: int = 60
    # The address ranges of the reverse proxies in front of this BFF. Empty (the default)
    # ignores X-Forwarded-For and throttles on the direct peer — behind an ingress that is
    # the *controller's* address for every user, collapsing the throttle into one shared
    # bucket where one person fumbling a password throttles everyone, break-glass included.
    #
    # Ranges rather than a hop count, matching the gateway's `security.trusted_proxy_cidrs`
    # (`ratelimit.py`) — one concept, one spelling across both halves. A count says how far
    # to walk but not whether the request came through the proxy at all, so a caller who
    # reaches this pod directly still supplies their own bucket key. A trust set answers
    # both: the walk starts at the TCP peer and only proceeds while each hop is ours.
    trusted_proxy_cidrs: list[str] = field(default_factory=list)
    # Federated identity (OIDC, ADR-0007). When enabled, the BFF runs an Authorization
    # Code + PKCE login against the IdP and relays the user's access token upstream
    # (Mode A token passthrough), so the gateway authorizes the real user. Local
    # password login stays available as break-glass/bootstrap.
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # TM-I-05: accept a plaintext http:// issuer. Default false; refused at construction.
    oidc_allow_plaintext_issuer: bool = False
    oidc_redirect_url: str = ""
    oidc_scopes: str = "openid profile email offline_access"
    oidc_post_login_redirect: str = "/"
    # Where the IdP sends the browser after RP-initiated (single) logout. Must be
    # registered with the IdP as a post_logout_redirect_uri. Empty → omit the param.
    oidc_post_logout_redirect: str = ""

    # Which tenant this deployment serves (ADR-0013 §4). Only consulted to decide whether
    # a provider session's act-on-tenant grant names *this* stack — so empty, the default,
    # admits no provider session at all and every existing tenant deployment is unchanged.
    # Deliberately the same name the gateway uses for the same concept (`gateway.tenant_id`,
    # ADR-0013 §11): one name for one thing across both halves.
    tenant_id: str = ""
    #: Where a PROVIDER reaches this tenant's gateway from outside the cluster — the ingress,
    #: not `gateway_url`. The two are routinely different and must not be derived from each
    #: other: `gateway_url` is the in-cluster service address this BFF dials, which is
    #: unreachable and meaningless to anyone else. Shown to a tenant admin so they can hand it
    #: to their provider alongside an enrolment invitation (ADR-0024 §10).
    #:
    #: Empty is a legitimate state, and the console says so rather than guessing: an address
    #: invented here would be handed to a provider and fail at redemption, which is a worse
    #: outcome than admitting the deployment never configured one.
    public_gateway_url: str = ""
    #: Where a TENANT reaches this provider's catalog from outside the provider's cluster.
    #: The exact mirror of `public_gateway_url` above, and needed for the same reason:
    #: `catalog_service_url` is the address THIS BFF dials, and handing it to a tenant during
    #: enrolment tells them to resolve a name that exists only in the provider's cluster.
    #:
    #: Enrolment REFUSES rather than falling back to `catalog_service_url`. A fallback here
    #: produces an enrolment that looks completely successful and leaves the tenant's console
    #: unable to reach the catalog forever, reporting a DNS error that names nothing an
    #: operator could act on (ADR-0024 §10's step 9 — "fails quietly, and reads as the catalog
    #: being down while it is healthy").
    public_catalog_url: str = ""

    # --- Provider plane (ADR-0013 §2/§3) --------------------------------------
    # A SECOND IdP, for the provider's own operators. Configuring it turns this BFF into
    # the provider console; the plane of a session is decided by which of the two IdPs
    # authenticated, never by a request parameter.
    #
    # ⚠️ A tenant-stack BFF should NOT configure this. Putting cross-tenant machinery
    # inside a per-tenant deployment is the same mistake ADR-0013 §5 refuses for the
    # gateway — and it is the only topology in which a cross-plane leak is even possible.
    provider_oidc_enabled: bool = False
    provider_oidc_issuer: str = ""
    provider_oidc_client_id: str = ""
    provider_oidc_client_secret: str = ""
    provider_oidc_redirect_url: str = ""
    provider_oidc_scopes: str = "openid profile email"
    # provider-IdP group → provider scope, as JSON. No fallback: an unmapped group grants
    # nothing (§6a's rule, applied on this side). Elevated scopes are refused here — they
    # are time-boxed audited grants, not group memberships.
    provider_group_scopes: dict = field(default_factory=dict)
    provider_groups_claim: str = "groups"
    # `provider_entitlement_claim` (the estate-navigation claim), `provider_step_up_acr`/
    # `provider_step_up_redirect_url` (the step-up context), `provider_grant_claim`
    # (the IdP-minted grant claim) and `provider_step_up_scope_template` (the step-up scope
    # request) all named parts of the act-on-tenant/elevated-grant mechanism removed at
    # ADR-0017 slice 6 (`grants.py`, `routers/provider.py` — deleted; see those commits).
    # Not reintroduced speculatively: ADR-0017's replacement (slice 7) has a different shape
    # and will need its own settings, not a renaming of these.
    #
    # The tenant registry (ADR-0021, scoped) — the provider console's own directory of
    # which tenants exist and where each one's gateway lives, as a JSON array of
    # {tenant_id, display_name, gateway_url}. See tenant_registry.py. Populated by tenant
    # provisioning fulfilment (ADR-0024), never written by the console itself. Empty is a
    # valid "no tenants yet", not a config error.
    provider_tenant_registry: str = ""

    # --- Audit (gateway F-57 model, ADR-0013 §9/§10) --------------------------
    # File the hash-chained audit is appended to. Empty → records still chain and still
    # go to stdout, but the chain restarts at genesis on every boot because there is no
    # tail to re-seed from. Set this anywhere the audit is expected to be evidence.
    audit_path: str = ""
    # Which tenant this stack serves. Stamped on every record in the clear, because it is
    # what tells a reader which content key applies — see audit.py on what survives a shred.
    audit_tenant: str = "default"
    # Fernet key encrypting this tenant's record content, so offboarding can be a key
    # destruction rather than a row deletion (ADR-0013 §10). Empty → content is written in
    # the clear and crypto-shredding is unavailable; the chain is unaffected either way.
    audit_content_key: str = ""
    # HMAC key producing stable, non-reversible handles for cross-plane (provider) actors
    # (ADR-0013 §9). Unkeyed pseudonyms would be reversible by dictionary attack over a
    # staff list, so without this the writer emits an opaque constant rather than a name.
    audit_pseudonym_key: str = ""

    # --- Catalog service (ADR-0020) --------------------------------------------------
    # Empty → the catalog feature is disabled (named condition, ADR-0020 §7 — never
    # inferred from an empty device-type list). Both must be set for provider curation
    # or the tenant claim view to work; see `catalog_client.CatalogClient`.
    catalog_service_url: str = ""
    # ⚠️ **Per-deployment, not per-estate** (ADR-0020 §7a). On the provider console this is
    # the privileged catalog credential; on a tenant-plane BFF it is THAT TENANT'S OWN token,
    # which the provider provisions per tenant. Copying the provider's value into a tenant's
    # deployment hands that tenant every other tenant's catalog data — the catalog cannot
    # detect it (the request authenticates correctly, as the provider), so `CatalogClient`
    # checks its own identity against `tenant_id` on first use instead.
    catalog_api_token: str = ""


def _split(csv: str) -> list[str]:
    return [item.strip() for item in csv.split(",") if item.strip()]


def _secret(env_name: str, file_env: str) -> str:
    """A secret from ``env_name``, or from the file named by ``file_env`` if the var is
    empty (the standard ``*_FILE`` convention). Lets the lite stack share the gateway key
    the gateway self-provisioned to a mounted volume — no secret copied between containers.

    Both branches strip. The file branch always did, for the obvious reason that a file
    written by `echo` or `openssl rand > f` ends in a newline. The env branch needs it for
    exactly the same reason one step removed: `kubectl create secret --from-file=` — the
    documented way to build these — carries that newline into the environment variable, so
    a value that looks correct in `printenv` fails every comparison against what a client
    actually sends.
    """
    value = os.getenv(env_name, "").strip()
    if value:
        return value
    file_path = os.getenv(file_env, "").strip()
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""
    return ""


class ProxyTrustError(ValueError):
    """Raised at startup for a proxy-trust configuration that cannot be honoured safely."""


def _trusted_proxy_cidrs() -> list[str]:
    """The proxy ranges to trust in X-Forwarded-For.

    ``TRUSTED_PROXY_CIDRS`` is the setting: a comma-separated list of networks or bare
    addresses (``10.244.0.0/16, 172.18.0.5``). Empty means the header is ignored entirely.

    ``TRUST_FORWARDED_FOR`` and ``TRUSTED_PROXY_HOPS`` are recognised **only so that setting
    them fails loudly**, the same treatment ``COOKIE_DOMAIN`` gets above. Both said "trust
    this header" without saying whose hops are yours, and trusting it without that is what
    lets any caller choose their own throttle bucket. Silently ignoring them would be worse
    than refusing: the deployment would boot, look configured, and quietly return every user
    to one shared bucket. Refusing names the replacement instead.

    Invalid entries raise rather than being skipped -- a typo'd CIDR dropped from the trust
    set re-opens the hole it exists to close.
    """
    raw = os.getenv("TRUSTED_PROXY_CIDRS", "").strip()
    values = _split(raw)
    if values:
        return values
    legacy = [
        name
        for name in ("TRUST_FORWARDED_FOR", "TRUSTED_PROXY_HOPS")
        if os.getenv(name, "").strip() not in ("", "false", "0", "no")
    ]
    if legacy:
        raise ProxyTrustError(
            f"{' and '.join(legacy)} is set but is no longer honoured. Trusting "
            "X-Forwarded-For without knowing which hops are yours lets any caller choose "
            "their own throttle bucket, so a hop count is not enough. Set "
            "TRUSTED_PROXY_CIDRS to the address range(s) of your reverse proxies instead "
            "(e.g. TRUSTED_PROXY_CIDRS=10.244.0.0/16), and remove "
            f"{' and '.join(legacy)}. Leave it empty to throttle on the direct peer."
        )
    return []


def _json_map(env_name: str) -> dict:
    """A ``{"group": "scope"}`` map from a JSON env var.

    Malformed JSON raises rather than defaulting to an empty map: a group→scope table that
    silently becomes ``{}`` grants nothing and looks like a permissions bug for as long as
    it takes someone to find the typo. Failing at startup names the real cause.
    """
    raw = os.getenv(env_name, "").strip()
    if not raw:
        return {}
    import json

    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"{env_name} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()):
        raise ValueError(f"{env_name} must be a JSON object of string→string")
    return parsed


def load_settings() -> Settings:
    return Settings(
        gateway_url=os.getenv("GATEWAY_URL", "http://localhost:8000"),
        # The gateway versions its management API under a prefix (e.g. /v1/devices).
        # Override only when the gateway introduces a new version (e.g. /v2). The
        # unversioned probes (/health, /readyz) are not proxied by the BFF.
        gateway_api_prefix=os.getenv("GATEWAY_API_PREFIX", "/v1"),
        # Admin bearer token for the gateway API (server-side only). Falls back to
        # GATEWAY_TOKEN_FILE so the lite stack can read the key the gateway generated.
        gateway_token=_secret("GATEWAY_API_TOKEN", "GATEWAY_TOKEN_FILE"),
        # UI login passwords → role. Leave a role's password empty to disable it.
        # Stripped: these are compared against what a human types into a browser form,
        # which can never carry the trailing newline that `--from-file` puts in the
        # environment. Unstripped, the correct password fails as "Invalid credentials" —
        # the one message that sends an operator to re-check a password that was right,
        # on the break-glass path they reached for because something else was broken.
        ui_admin_password=os.getenv("UI_ADMIN_PASSWORD", "").strip(),
        ui_viewer_password=os.getenv("UI_VIEWER_PASSWORD", "").strip(),
        # MUST be overridden in production; signs the session cookie. Booting with this
        # default while COOKIE_SECURE is on is refused in create_app().
        # Stripped for the same reason as the passwords, though the consequence is milder:
        # this signs the session cookie, so a whitespace-tainted value is self-consistent
        # and works. Normalising it costs a one-time re-login on upgrade and buys one rule
        # that holds for every secret read here, rather than a per-value judgement call
        # about whether this particular one happens to be compared against outside input.
        session_secret=os.getenv("SESSION_SECRET", DEFAULT_SESSION_SECRET).strip(),
        session_redis_url=os.getenv("SESSION_REDIS_URL", ""),
        session_ttl_seconds=int(os.getenv("SESSION_TTL_SECONDS", "28800")),  # 8 hours
        prometheus_url=os.getenv("PROMETHEUS_URL", ""),
        loki_url=os.getenv("LOKI_URL", ""),
        # Optional link to central Grafana — surfaced in the UI's monitoring view so
        # operators jump to full dashboards rather than rebuilding them here.
        grafana_url=os.getenv("GRAFANA_URL", ""),
        cors_origins=_split(os.getenv("CORS_ORIGINS", "")),
        cookie_secure=os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
        cookie_domain=os.getenv("COOKIE_DOMAIN", "").strip(),
        login_max_failures=int(os.getenv("LOGIN_MAX_FAILURES", "5")),
        login_window_seconds=int(os.getenv("LOGIN_WINDOW_SECONDS", "60")),
        trusted_proxy_cidrs=_trusted_proxy_cidrs(),
        # OIDC (federated identity). Disabled unless OIDC_ENABLED is truthy AND an
        # issuer + client id are configured (validated in OIDCClient).
        oidc_enabled=os.getenv("OIDC_ENABLED", "false").lower() in ("1", "true", "yes"),
        oidc_issuer=os.getenv("OIDC_ISSUER", ""),
        oidc_client_id=os.getenv("OIDC_CLIENT_ID", ""),
        oidc_client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
        oidc_allow_plaintext_issuer=os.getenv("OIDC_ALLOW_PLAINTEXT_ISSUER", "false").lower() in ("1", "true", "yes"),
        # Must exactly match a redirect URI registered with the IdP, e.g.
        # https://ui.example.com/auth/oidc/callback
        oidc_redirect_url=os.getenv("OIDC_REDIRECT_URL", ""),
        oidc_scopes=os.getenv("OIDC_SCOPES", "openid profile email offline_access"),
        oidc_post_login_redirect=os.getenv("OIDC_POST_LOGIN_REDIRECT", "/"),
        oidc_post_logout_redirect=os.getenv("OIDC_POST_LOGOUT_REDIRECT", ""),
        tenant_id=os.getenv("TENANT_ID", "").strip(),
        public_gateway_url=os.getenv("PUBLIC_GATEWAY_URL", "").strip().rstrip("/"),
        public_catalog_url=os.getenv("PUBLIC_CATALOG_URL", "").strip().rstrip("/"),
        # Provider plane (ADR-0013). Absent → this BFF serves the tenant plane only, which
        # is what a tenant-stack deployment should look like.
        provider_oidc_enabled=os.getenv("PROVIDER_OIDC_ENABLED", "false").lower() in ("1", "true", "yes"),
        provider_oidc_issuer=os.getenv("PROVIDER_OIDC_ISSUER", ""),
        provider_oidc_client_id=os.getenv("PROVIDER_OIDC_CLIENT_ID", ""),
        provider_oidc_client_secret=_secret("PROVIDER_OIDC_CLIENT_SECRET", "PROVIDER_OIDC_CLIENT_SECRET_FILE"),
        provider_oidc_redirect_url=os.getenv("PROVIDER_OIDC_REDIRECT_URL", ""),
        provider_oidc_scopes=os.getenv("PROVIDER_OIDC_SCOPES", "openid profile email"),
        provider_group_scopes=_json_map("PROVIDER_GROUP_SCOPES"),
        provider_groups_claim=os.getenv("PROVIDER_GROUPS_CLAIM", "groups"),
        # Not itself a secret, but the same env-or-file shape is convenient for a value a
        # GitOps pipeline mounts as a file rather than an inline env var.
        provider_tenant_registry=_secret("PROVIDER_TENANT_REGISTRY", "PROVIDER_TENANT_REGISTRY_FILE"),
        # Audit. AUDIT_PATH defaults under BFF_STATE_DIR when the lite bootstrap is in
        # play, so a home box gets a durable, re-seedable chain without configuring one.
        audit_path=os.getenv("AUDIT_PATH", ""),
        audit_tenant=os.getenv("AUDIT_TENANT", "default"),
        # ⚠️ UPGRADE NOTE. These two are key *material*, not values compared against
        # something a client sends: a trailing newline here is self-consistent and works.
        # They still go through `_secret`, which now strips both branches — so a deployment
        # that supplied a key via an env var with surrounding whitespace derives a
        # different key after this change, and records sealed under the old one no longer
        # decrypt. That divergence already existed and was worse for being invisible: the
        # file branch has always stripped, so the same key material delivered as a file and
        # as an env var produced two different keys. Made consistent deliberately. An
        # affected deployment -- one whose AUDIT_*_KEY env var has surrounding whitespace --
        # must either re-state the key without it (the chain then verifies as before,
        # because the stripped value is what the file branch would already have produced)
        # or archive the existing chain before upgrading. Check with:
        #   kubectl exec deploy/device-mcp-ui-bff -- \
        #     python3 -c "import os;v=os.environ.get('AUDIT_CONTENT_KEY','');print(v!=v.strip())"
        audit_content_key=_secret("AUDIT_CONTENT_KEY", "AUDIT_CONTENT_KEY_FILE"),
        audit_pseudonym_key=_secret("AUDIT_PSEUDONYM_KEY", "AUDIT_PSEUDONYM_KEY_FILE"),
        catalog_service_url=os.getenv("CATALOG_SERVICE_URL", ""),
        catalog_api_token=_secret("CATALOG_API_TOKEN", "CATALOG_API_TOKEN_FILE"),
    )
