# Device MCP Gateway — UI

A **separate, optional** management UI for the [Device MCP Gateway](../device-mcp-gateway).
Deployed independently; the gateway has **no dependency** on it (it only added a small
aggregate endpoint, `GET /admin/overview`). It covers device management (register/edit/
remove, diagnostics, tool explorer, dead-letter queue), a monitoring view, and federated
identity (OIDC SSO with per-user token passthrough).

## Architecture — thin BFF + SPA

```
  Browser (SPA: React + Vite + TS)
      │  signed cookie carrying only a session id (no token, no role in the browser)
      ▼
  BFF (FastAPI)  ── holds the gateway admin token + server-side session store, authorizes by role
      │
      ├──► Gateway API        (device CRUD, /admin/overview, /metrics/summary)
      ├──► Prometheus query    (phase 2 — monitoring panels)
      └──► Loki / Splunk query (phase 2 — logs; the gateway is never in the log path)
```

**Why a BFF?** The browser must never hold the gateway admin credential — or any token.
Session content (the role; for OIDC the user's tokens) lives in a **server-side session
store** (`bff/app/sessions.py`: in-memory by default, Redis via `SESSION_REDIS_URL` for
multi-replica deploys); the cookie carries only an opaque signed session id. The BFF maps
that session to a role (`admin`/`viewer`, mirroring the gateway's RBAC) and proxies
allowed calls upstream.

## What's in the repo

| Path | What |
|------|------|
| `bff/` | FastAPI BFF — `auth` (login/logout/me), `api` (proxy: overview, device CRUD incl. `PUT`, per-device diagnostics + tools, endpoint-fingerprint approval, dead-letter inspect/replay/drain, metrics summary, Prometheus/Loki + monitoring meta), session + role gating. Tests included. |
| `web/` | React + Vite + TypeScript SPA — login, device list + counts, a **full register/edit form** (auth `api_key`/`oauth2`, `spec_url`, rate limit; create via `POST`, edit via `PUT`), remove, a **device-detail panel** (diagnostics + **endpoint fingerprint** + tool explorer + dead-letter queue), and a **Monitoring view** (critical-metric tiles + central-monitoring pointers + recent logs). Typed client (`src/api.ts`) over the BFF. |
| `deploy/kubernetes/` | Own namespace, BFF + web Deployments/Services, Ingress, NetworkPolicies (BFF egress to gateway/Prometheus/Loki; web egress to BFF only), kustomization. Secrets via `secret.example.yaml`. |
| `docker-compose.yml` | Local build/preview of BFF + web. |

## Quickstart (local)

Run the gateway (embedded mode is fine) on `:8000`, then:

```bash
cp .env.example .env            # set GATEWAY_API_TOKEN + passwords

# BFF
make bff-install && make bff-run        # http://localhost:8090

# SPA (separate terminal) — Vite proxies /api and /auth to the BFF
make web-install && make web-dev        # http://localhost:5173
```

Or build both as containers: `make up` (web on `:8080`, proxying to the BFF).

## Lite / home deployment (Raspberry Pi, mini-PC)

To run this UI **together with** the gateway as a single low-power stack — embedded mode,
local-only login, secrets generated on first boot, amd64 or arm64 — use the gateway repo's
`docker-compose.lite.yml`. It builds the BFF and web images from this repo (kept side by
side) or pulls the published `:lite` images.

Canonical guide: **[../device-mcp-gateway/docs/lite-deploy.md](../device-mcp-gateway/docs/lite-deploy.md)**.

## Configuration (BFF env)

| Var | Purpose |
|-----|---------|
| `GATEWAY_URL` | Gateway API base URL |
| `GATEWAY_API_PREFIX` | Gateway management-API version prefix (default `/v1`; change only for a future `/v2`) |
| `GATEWAY_API_TOKEN` | The BFF's **own** gateway credential (server-side only), presented when relaying a *password* session — which has no per-user token to pass through. Point it at a named `gateway.rbac` entry with `role: console`, **not** at the gateway's admin key: see the note below |
| `UI_ADMIN_PASSWORD` / `UI_VIEWER_PASSWORD` | Local break-glass login password → role (empty disables) |
| `SESSION_SECRET` | Signs the session-id cookie and the OIDC login transaction (`openssl rand -hex 32`). The BFF **refuses to start** with the default value when `COOKIE_SECURE=true` |
| `SESSION_REDIS_URL` | Shared server-side session store. **Required for >1 BFF replica** (the K8s overlay runs 2 — no session affinity); empty = in-memory store, right for a single replica |
| `SESSION_TTL_SECONDS` | Server-side session lifetime (default `28800` = 8 h) |
| `COOKIE_SECURE` | `true` behind TLS |
| `COOKIE_DOMAIN` | **Refused.** Recognised only so that setting it fails loudly. The session cookie is host-scoped by construction, and per-tenant subdomains are an isolation boundary only while it stays that way — a cookie on `.example.com` is sent to every tenant's console beneath it, so one tenant's browser carries a session into another's portal with nothing appearing to break |
| `LOGIN_MAX_FAILURES` / `LOGIN_WINDOW_SECONDS` | Break-glass password throttle: after this many failed attempts from one client IP within the window, further attempts get `429` until it rolls off (defaults `5` / `60`) |
| `TRUSTED_PROXY_HOPS` | How many reverse proxies sit in front of the BFF (default `0`; the shipped Kubernetes manifests put one ingress in front, so they set `1`). At `0` the throttle keys on the direct peer — behind an ingress that is the controller's address for **every** user, so one person fumbling a password throttles everyone, break-glass included, and the audited lockout names the ingress instead of whoever was being brute-forced. Set it to the hop count that actually exists and no higher: `X-Forwarded-For` is a list the caller can prepend to, and the value is read from the right, so each hop you claim beyond the real ones is one entry the caller gets to write. `TRUST_FORWARDED_FOR=true` is still honoured as one hop |
| `OIDC_ENABLED` | Turn on federated SSO (Authorization Code + PKCE). See **Federated identity** below |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | IdP issuer URL + client credentials (omit the secret for a public/PKCE-only client) |
| `OIDC_REDIRECT_URL` | This BFF's callback, registered with the IdP (`…/auth/oidc/callback`) |
| `OIDC_SCOPES` / `OIDC_POST_LOGIN_REDIRECT` | Requested scopes (include one yielding a gateway-audience access token; defaults include `offline_access` so the IdP issues a refresh token for silent refresh — drop it if your IdP rejects it) / where to land after login |
| `OIDC_POST_LOGOUT_REDIRECT` | Where the IdP returns the browser after RP-initiated (single) logout; must be registered with the IdP. Empty = omit. Used only if the IdP exposes an `end_session_endpoint` |
| `PROVIDER_OIDC_ENABLED` | Turn on the **provider plane** — a second IdP for the platform's own operators (ADR-0013 §2). ⚠️ Leave off in a tenant-stack deployment; see **The provider plane** below |
| `PROVIDER_OIDC_ISSUER` / `PROVIDER_OIDC_CLIENT_ID` / `PROVIDER_OIDC_CLIENT_SECRET` | The provider IdP's issuer + client credentials (also honours `PROVIDER_OIDC_CLIENT_SECRET_FILE`) |
| `PROVIDER_OIDC_REDIRECT_URL` | The provider callback, registered with the provider IdP (`…/auth/provider/callback`) |
| `PROVIDER_GROUP_SCOPES` | JSON `{"group": "provider:scope"}`. **No fallback** — an unmapped group grants nothing. Only `provider:monitor` / `provider:admin` are mappable |
| `PROVIDER_GROUPS_CLAIM` | Claim carrying provider-IdP group membership (default `groups`) |
| `TENANT_ID` | Which tenant this deployment serves — consulted by the catalog claim flow (ADR-0020) to say which tenant's assignments/claims apply. Empty (the default) means no existing tenant-stack deployment needs a config change |
| `PROMETHEUS_URL` / `LOKI_URL` | Monitoring sources, proxied by the BFF for the Monitoring view (critical-metric tiles / recent logs). Empty = lean on central monitoring |
| `GRAFANA_URL` | Optional link to central Grafana, surfaced in the Monitoring view |
| `CORS_ORIGINS` | Only needed if the SPA is served from a different origin than the BFF |
| `AUDIT_PATH` | File the hash-chained audit is appended to. Empty = records still chain and go to stdout, but the chain **restarts at genesis on every boot** because there is no tail to re-seed from. Set it anywhere the audit is meant to be evidence |
| `AUDIT_TENANT` | Which tenant this stack serves (default `default`). Stamped on every record in the clear — it is what tells a reader which content key applies |
| `AUDIT_CONTENT_KEY` | Fernet key encrypting record content, so offboarding a tenant is a key destruction rather than a row deletion. Empty = content in the clear and **no crypto-shredding**; the chain is unaffected either way. Also `AUDIT_CONTENT_KEY_FILE` |
| `AUDIT_PSEUDONYM_KEY` | HMAC key producing stable, non-reversible handles for cross-plane (provider) actors. Empty = the writer emits an opaque constant rather than a real identity, because an unkeyed pseudonym is reversible by dictionary attack. Also `AUDIT_PSEUDONYM_KEY_FILE` |
| `CATALOG_SERVICE_URL` | The provider-plane device catalog's base URL (ADR-0020) — a separate service (`device_mcp_catalog/` in the gateway repo), not the BFF's own storage. Empty disables catalog curation/claiming as a named condition rather than an empty device-type list |
| `CATALOG_API_TOKEN` | This BFF's shared bearer token for the catalog service (also `CATALOG_API_TOKEN_FILE`) — the catalog's only caller in phase 1, so one token rather than a scope model |

> **`GATEWAY_API_TOKEN` is the console's identity, not the gateway's break-glass key — and
> conflating the two is what ADR-0023 slice 4 separates.** They used to be the same value,
> which had two consequences. Every console password login authenticated to the gateway as
> `key:legacy`, indistinguishable from any other holder of that key; and once
> `gateway.api_key` becomes break-glass in an OIDC deployment, ordinary console traffic would
> fire a high-severity audit event and inherit a 90-day expiry on the login path.
>
> Give the BFF its own named entry instead. On the gateway:
>
> ```yaml
> gateway:
>   rbac:
>     - name: bff-password-sessions
>       key: "secret://console/bff#token"   # a reference, never a literal - config.yaml is a ConfigMap
>       role: console
> ```
>
> `console` is `operator` + `caller` — device management, metrics and tool invocation — and
> deliberately carries **no `backup:*` scope**. The BFF already refuses password sessions on
> all four backup/restore routes, because the admin token it proxied with held every backup
> scope and admitting one there "is a complete credential dump". The role moves that
> guarantee into the gateway, where a bug on this side cannot undo it.
>
> The entry is **unflagged** on purpose. This is continuous machine traffic, not break-glass;
> flagging it would page on every quiet-gap boundary and expire the console's login path.
>
> Cutover order matters: create the entry, point this variable at it, **verify no request
> still audits as `key:legacy`**, and only then flag `gateway.api_key`. See
> `deploy/kubernetes/configmap.yaml` in the gateway repo for the Secret projection — a
> reference resolves to at least three path components, so a flat `--from-literal` Secret
> cannot satisfy one.


## Audit (tamper-evident)

The BFF keeps its **own** hash-chained audit, on the gateway's F-57 model. It is not
redundant with the gateway's: once provider federation ships
([ADR-0012](https://github.com/benwold-lgtm/MCP-Gateway/blob/main/docs/adr/0012-federation-credential-model.md)),
the gateway no longer sees the real human — it sees whatever credential the BFF presented.
Today per-user OIDC relay hides that gap; federation ends it. Some events are also invisible
to the gateway by construction: a **failed login** or a throttle lockout never reaches it.

What gets recorded: every mutation (device register/update/delete, dead-letter replay/drain)
and every authentication event (password login success/failure/lockout, OIDC login, logout),
including the ones that were *refused*, since "who was refused what" is the question an
audit is most often asked. Reads are deliberately **not** recorded — per-user relay means the
gateway's own chain already has them, so duplicating would add noise rather than
accountability. That changes when a provider session's reads reach a tenant (§9).

Three properties, per
[ADR-0013](https://github.com/benwold-lgtm/MCP-Gateway/blob/main/docs/adr/0013-two-plane-tenancy-and-the-provider-plane.md)
§9/§10:

- **Tamper-evident.** Each record commits to `sha256(seq, prev, payload)` and links to its
  predecessor, so an edit, deletion or reorder is detectable by replay. Records carry an
  instance id and verify as one sub-chain *per writer*, so several replicas appending to one
  sink are not mistaken for tampering.
- **The actor is pseudonymized at write time**, never at render time — a hash-chained record
  cannot be redacted afterwards without breaking verification, so the substitution has to
  happen before the bytes are committed. Handles are stable, so a tenant can tell one
  engineer from two.
- **Content is encrypted per tenant**, so offboarding destroys a key rather than deleting
  rows from a chain that spans tenants.

**The hash covers the ciphertext, not the plaintext.** That is what lets a shredded tenant's
records still verify — otherwise erasure would cost tamper-evidence exactly when you most
need to prove the log was not altered. The consequence, stated plainly: the tenant tag,
timestamp and chain position survive a shred, so you can still see *that* tenant X acted N
times and when. Nothing about what, to what, or by whom survives.

Verifying a log:

```python
from app.audit import verify_chain
ok, detail = verify_chain("/var/lib/bff/audit.log")   # needs no content key
```

## Federated identity (OIDC SSO)

Set `OIDC_ENABLED=true` (plus the `OIDC_*` vars) to let users sign in through your IdP
(on-prem AD via ADFS/Keycloak, or a cloud IdP — Entra/Okta/Auth0/Google). The flow:

```
Browser ──/auth/oidc/login──> BFF ──Auth Code + PKCE──> IdP
        <─────302 callback──── BFF <──code→tokens──────┘
BFF validates the ID token (JWKS sig, iss/aud/exp, nonce), stores the user's tokens
in the server-side session store, then the browser carries only a session-id cookie.
```

When a relayed access token expires, the BFF **silently refreshes** it: a gateway `401`
triggers a `refresh_token` grant (server-side) and the call is retried once, so the user
isn't bounced to the login screen mid-session. This needs a refresh token, which the IdP
issues when `offline_access` is granted (in the default `OIDC_SCOPES`). If the refresh
fails (revoked/expired), the session ends and RP-initiated logout applies. Refresh runs
under a **per-session lock** in the session store, so concurrent requests racing an
expiry refresh exactly once — safe with refresh-token rotation.

There are **two kinds of session**:

- **OIDC** — the BFF relays the **user's own access token** to the gateway (token
  passthrough), so the **gateway** authorizes on that user's real scopes and the audit
  shows the real user. The BFF does not re-authorize. For this to work the IdP must mint an
  access token whose audience the gateway accepts — set the matching `gateway.oidc` config
  on the gateway (issuer, audience, `group_roles`) per its
  [ADR-0007](https://github.com/benwold-lgtm/MCP-Gateway/blob/main/docs/adr/0007-federated-identity-oidc-and-gateway-rbac.md).
- **password** — the existing local **break-glass / bootstrap** login. It has no per-user
  token to pass through, so it proxies upstream with the BFF's own `GATEWAY_API_TOKEN` and
  the BFF enforces the admin/viewer distinction itself. That token should be a `console`-role
  entry of the BFF's own, not the gateway's admin key — see the note under the settings table.
  Keep at least the admin password even with SSO on (an IdP outage must not lock you out).

The SPA shows a **"Sign in with SSO"** button when OIDC is enabled (alongside or instead of
the password form, per `/auth/config`) and **gates every write affordance on the gateway's
scopes** — it reads `/auth/me`, whose scopes come from the gateway's own whoami for OIDC
sessions, so the UI and gateway authorization can't drift.

## Roadmap (phasing)

1. **Device management** ✅ — list/remove over the gateway REST API, status from `/admin/overview`.
2. **Device detail** ✅ — per-device diagnostics ("why is my device down?"), a tool explorer (the generated MCP tools + their input schemas), and a **recent tool-set change** panel (added/removed/changed + breaking flag), from `/devices/{h}/diagnostics`, `/devices/{h}/tools`, and `/devices/{h}/tools/diff`.
3. **Register / edit** ✅ — a full create + edit form (auth `api_key`/`oauth2`, `spec_url`, rate limit), `POST` to register and `PUT` to edit; edit pre-fills from the gateway and omits `auth` by default so stored credentials are preserved.
4. **Monitoring + DLQ** ✅ — a lightweight native monitoring view: critical at-a-glance metric tiles (Prometheus instant queries) + a recent-logs panel (Loki LogQL), both proxied through the BFF, plus first-class pointers to **central monitoring** (the gateway's `:9100/metrics` scrape endpoint and an optional Grafana link); intentionally not a full monitoring app. Plus a per-device **dead-letter queue** panel in device detail (inspect any session; replay/drain admin-only; distributed mode).
5. **Federated identity** ✅ — OIDC SSO at the BFF (Authorization Code + PKCE) with per-user
   token passthrough to the gateway and local passwords kept as break-glass (ADR-0007). The
   SPA offers a "Sign in with SSO" button and **gates write affordances on the gateway's
   scopes** (`/auth/me`), so UI and gateway authorization stay in lockstep.
6. **Server-side sessions** ✅ — session content (role, OIDC tokens) moved out of the
   cookie into a store (memory, or Redis via `SESSION_REDIS_URL` for multi-replica);
   OIDC refresh serialised per session. Login throttling on the break-glass password ✅.
7. **Endpoint fingerprint** ✅ — the device-detail view renders the gateway's endpoint
   fingerprint (ADR-0015) and offers the approval decision when a device's TLS key has
   changed. See below for the rule that shapes it.
8. **Live** — SSE/WS device status, finer per-scope views.

## The provider plane (ADR-0013)

Two populations, not one. A **tenant user** belongs to a single tenant and signs in to that
tenant's IdP. A **provider operator** is cross-tenant by design — the platform's own staff,
running the manager-of-managers console — and signs in to the *provider's* IdP.

`plane` (`tenant` | `provider`) is set **at login, from which IdP authenticated**, and never
from a request parameter. The two login routes are separate endpoints (`/auth/oidc/login`
and `/auth/provider/login`) for exactly that reason: with no `plane=` input there is nothing
for a handler to forget to validate.

### Deployment topology — a tenant BFF should not configure the provider IdP

**Setting both IdPs in one process is refused at startup.** A tenant's BFF lives inside the
tenant's stack, and putting cross-tenant machinery there is the same mistake ADR-0013 §5
refuses for the gateway. This is enforced rather than advised, for the reason §11 used to
reject a whole design option: a bound that lives in a README is not a bound.

- **Tenant stack** — set `OIDC_*` only. `PROVIDER_OIDC_ENABLED` stays false, so a
  provider-plane session cannot be minted in that process.
- **Provider console** — a separate deployment with `PROVIDER_OIDC_*` set and `OIDC_*` unset.

Break-glass password login stays available in both, and is always tenant-plane.

**The startup refusal is per-process; the session store is not.** Two BFFs sharing one
`SESSION_REDIS_URL` would otherwise share the `bff:sess:{sid}` keyspace and resolve each
other's session ids. Session keys are therefore namespaced per deployment
(`bff:sess:provider:…` / `bff:sess:tenant:<tenant>:…`) — and the plane wall is kept as well
as the refusal, not instead of it, because it is what still holds if a session does cross.

### The provider plane today (ADR-0017 slice 6)

| | |
|---|---|
| Holds | `provider:*` scopes, mapped from provider-IdP groups (`PROVIDER_GROUP_SCOPES`) |
| Never holds | any gateway scope; the two vocabularies are reported separately by `/auth/me` |
| Tenant data plane (`/api/*`) | **refused unconditionally**, for now |
| Catalog (`/provider/catalog/*`) | reachable — see below, unaffected |

ADR-0013's **act-on-tenant** grant — cross-tenant power exercised, not held, for a bounded,
justified, audited window — and the **elevated grant** layered on top of it (a step-up
gating tool invocation) are both removed as of ADR-0017 slice 6. `app/grants.py` and
`app/routers/provider.py` are gone; `security.require_role` now refuses every provider-plane
session on the tenant data plane outright, rather than checking a grant that no longer
exists.

**Why remove rather than harden.** ADR-0017 inverts who asserts provider authority over a
tenant: instead of the provider's own console minting a grant and presenting it, the
*tenant's own gateway* mints a short-lived support credential once a tenant admin approves a
request the provider raised. That is a different mechanism, not a stronger version of this
one — porting the act-on-tenant machinery forward and then replacing it would have meant
maintaining two authorization models in parallel for no benefit. The replacement (raising a
request, polling for approval, the credential the gateway hands back) is ADR-0017 slice 7
(BFF) and slice 8 (UI); neither has shipped here yet, so the provider console currently shows
Devices/Monitoring/Backup as visible-but-disabled rather than reachable.

This is a real, temporary regression in what the provider console can do — and a deliberately
safe one. Refusing unconditionally is a fail-closed interim, not a silent gap: nothing here
was left half-migrated, and no route quietly stopped checking anything. See
[ADR-0017](https://github.com/benwold-lgtm/MCP-Gateway/blob/main/docs/adr/0017-provider-authority-is-delegated.md)
and the gateway repo's `docs/adr/README.md` item 7 for the full slice-by-slice history.

### Catalog (ADR-0020)

`provider:admin` also reaches `/provider/catalog/*` — curating device types and assigning
them to tenants — and this was never gated on act-on-tenant in the first place: curation and
assignment write to the catalog service's own storage, not a tenant's registry (§2:
"assignment is an offer"), so there was no tenant authority to hold. The BFF relays every
call to a separate service (`device_mcp_catalog/` in the gateway repo,
`CATALOG_SERVICE_URL`/`CATALOG_API_TOKEN` above) and holds none of it itself. Entirely
unaffected by the removal above.

`assigned_by` on an assignment is filled in from the session's own subject, never taken from
the request body — an unverified client-supplied actor would be worthless as an audit
attribution.

The claim flow (§4) — a tenant accepting an assigned device type into their own registry —
is a tenant-plane act and lives under `/api/catalog/*`, not here:

```
GET  /api/catalog/device-types       → this tenant's currently assigned device types
GET  /api/catalog/device-types/{id}  → one assigned type's version detail (404 if not assigned)
POST /api/catalog/{id}/claim         {hostname, base_url, auth?, rate_limit_rps?, expected_tls_spki_sha256?}
```

`claim` merges the type's current curated version (transport, upstream_kind, auth_kind,
spec_path, fingerprint_policy) with only the tenant-supplied fields above, and registers the
result via the gateway's ordinary `POST /devices` — the same route the free-type `DeviceForm`
uses, unmodified. `spec_path` is joined against the **tenant's own** `base_url`, never a
curator-side URL. A best-effort second call pins which version was claimed on the catalog
service; if the catalog is unreachable at that point the device registration still stands —
the miss is recorded as its own audit outcome (`device.claim.pin_unrecorded`) rather than
silently lost, since undoing an already-successful registration over a bookkeeping failure
would be the worse of the two problems.

**Upgrade offers (§4, slice 5)** — never blocking, never scheduled, never forced:

```
GET  /api/catalog/upgrades                    → offers: a claimed device whose pinned
                                                 version differs from the type's current one
POST /api/catalog/upgrades/{hostname}/accept  {device_type_id, version}
```

Each offer carries a diff between the two versions' curator-DECLARED `tool_set`s (never a
live measurement — the catalog has no tenant `base_url` to probe one with); `diff: null`
means neither version had one to compare, a distinct condition from an empty diffed result.
Accepting an offer only re-pins the claim on the catalog side (the existing
`POST /device-types/{id}/claims` route, called again with the new version) — it never
touches the gateway or the live device, unlike `claim` above. The panel renders nothing when
there's nothing to offer and nothing when the check itself fails, rather than a banner that
nags on a transient outage.

### Tool invocation, backup and restore (tenant plane)

```
POST /api/devices/{hostname}/tools/{tool}/invoke   {"arguments": {…}}   tools:call
GET  /api/admin/backup
POST /api/admin/backup       {"kind": "portable", "passphrase": "…"}
POST /api/admin/restore      {"archive": {…}, "dry_run": true}
```

Three rules, none of which is visible from the route list:

- **Tool invocation is one blocking call, not an MCP transport.** The route runs
  `initialize` → `tools/call` → teardown and returns the result. That forecloses incremental
  progress for a long-running call — an accepted trade, because the gateway's dispatch
  contract is one request and one response, so no transport can report progress today. In the
  console it is a form generated from the tool's own JSON Schema, on the device's tool list.
  Two things it does that a plain "run" button would not: it **converts each value to its
  declared type** (an HTML input yields a string, and `{"a": "2"}` against `type: integer` is
  refused upstream with `-32602`), and it **omits an argument the operator did not supply**
  rather than sending `""`, because a schema default applies only to an absent key. A JSON-RPC
  error arrives over HTTP 200, so the console reads the envelope rather than the status — and
  reports a refused call and a tool that ran and failed as different things, since one means
  fix the arguments and the other means go and look at the device.
- **Export is two requests, and restore is two clicks.** In the console, exporting *prepares*
  an archive (revealing a generated passphrase once, because nothing keeps a copy of it) and
  then downloads it — a native download cannot read the header the passphrase arrives in, so
  one request cannot deliver both. Restoring always previews first, and Apply is bound to a
  signature of the exact inputs that produced the preview: change the archive, the passphrase,
  the conflict mode or the dead-letter flag and it is withdrawn until you preview again. A
  two-step confirm is theatre unless the plan confirmed is the plan that runs.
- **`/api/admin/*` refuses the local break-glass login**, whatever its role. A password
  session proxies with the stack's *admin* gateway token, which already holds every
  `backup:*` scope — so admitting one there is a complete credential dump with no step-up
  behind it. Tool invocation stays open to break-glass: repairing a broken fleet is what
  that login is for. **A lite/home deployment therefore has no backup or restore in the
  console** — it runs SSO off, so a password session is all it has. That is deliberate:
  lite is a home test bed, and the gateway's own `/v1/admin/backup` is still reachable with
  the API key.

A restore with no `dry_run` in the body **is** a dry run: the BFF sets it explicitly rather
than relying on the gateway's default, so the destructive direction is not reachable by
omission through two layers.

## Endpoint fingerprint — three dimensions, never one badge

The gateway pins what a device *is* along three dimensions, and the UI is required to keep
them visually distinct:

| Group | Field(s) | What it is worth |
|-------|----------|------------------|
| **Authenticated** | `tls_spki_sha256` | Cryptographic. The **public-key** digest, not the certificate — a routine renewal reissues against the same key, so it stays quiet until the key itself moves. |
| **Self-reported** | `declared_name`, `declared_version` | Whatever the upstream chose to say about itself. A change signal; **spoofable**, and never evidence of identity. |
| **Behavioural** | `tools_revision` | What the device actually exposes. |

Collapsing these into one "verified" badge would lend the self-reported half a weight it has
not earned. There is no such badge, and the tests assert its absence. For the same reason the
state chip (`unpinned` / `pinned` / `pending approval`) describes **the pin**, not trust —
even "pinned" only means "the same key as last time", because the baseline itself was
trust-on-first-use and validated nothing.

Two related honesty rules the panel follows:

- An `http://` device has no certificate at all. Its missing pin is reported as a **fact**,
  not as a gap to close — a standing false alarm is how a control gets ignored.
- When a device sets no `fingerprint_policy` it **inherits** the fleet setting, and the
  gateway resolves the effective value at enforcement time without reporting it. The panel
  says "inherited" rather than naming a policy it cannot see.

Approving a changed key (`POST /api/devices/{hostname}/fingerprint/approve`) is admin-only
and recorded in the BFF's audit chain under the same action name the gateway uses,
`device.fingerprint.approve`, so the two chains describe one event.

**Known gap (gateway-side):** `DeviceSummary` carries no `fingerprint_state`, so the device
list cannot flag a device awaiting approval — it is only visible on the detail view. Closing
that needs one field on the gateway's list projection.

## Keep the contract typed (no manual drift)

The SPA's `Device`/`Overview` types are **derived from the gateway's OpenAPI**, not
hand-maintained:

- `web/gateway.openapi.json` is a committed snapshot of the gateway contract.
- `npm run gen:types` runs `openapi-typescript` to produce `web/src/gateway.d.ts`
  (gitignored), and `web/src/types.ts` re-exports its `DeviceSummary`/`OverviewResponse`.
- `typecheck`, `build`, `test`, and CI all run `gen:types` first, so a contract change
  that breaks the SPA fails the type-check **loudly** instead of drifting silently.

Refresh the snapshot when the gateway's API changes:

```bash
# from a running gateway:
curl -s http://localhost:8000/openapi.json -o web/gateway.openapi.json
cd web && npm run gen:types   # regenerate types; tsc will flag any incompatibility
```

The gateway gives these endpoints real response models (`OverviewResponse`,
`DeviceSummary`, …), so the generated types are meaningful rather than `unknown`.

`gen:types` only catches a contract change that breaks a type the SPA *consumes* — it
won't notice a renamed/moved path the BFF proxies (the bug that left the BFF calling
unversioned, pre-`/v1` paths). `npm run check:spec` closes that gap: point it at a live
gateway and it diffs the committed snapshot against it — paths and methods, **every
`components.schemas` shape** (property names *and* `required`), and the version.

```bash
GATEWAY_OPENAPI_URL=http://localhost:8000/openapi.json npm run check:spec
# or against a file:
GATEWAY_OPENAPI_FILE=../gateway/openapi.json npm run check:spec
```

⚠️ **With neither variable set, `check:spec` does not run** — it prints "DID NOT RUN" and
exits 0, because ordinary CI has no gateway to compare against. A green `check:spec` line in
a CI log is therefore usually the sound of nothing happening. Set `CHECK_SPEC_REQUIRED=1` in
any job that is meant to enforce it and a missing reference becomes a failure instead of a
shrug.

That default is why the snapshot once sat **two gateway releases stale**: the schema surface
had moved, paths and methods had not, and nothing said so. The schema diff now catches that
class — but only where the check actually runs. Refreshing the snapshot is still a manual
step somebody has to remember after a gateway API change.

One trap when refreshing from a source checkout: the gateway's `info.version` comes from
**installed package metadata**, so an editable install left on an older version emits a spec
labelled with the old version. Re-sync the gateway venv first, or the version line silently
agrees while the schemas do not.

```bash
# enforce against a running gateway (CI skips this step when neither var is set):
GATEWAY_OPENAPI_URL=http://localhost:8000/openapi.json npm run check:spec
# or against a file:  GATEWAY_OPENAPI_FILE=../path/to/openapi.json npm run check:spec
```

### Frontend tooling

```bash
cd web
npm install
npm run lint          # eslint (flat config) + prettier via format:check
npm run format        # prettier --write
npm run typecheck     # gen:types + tsc --noEmit
npm test              # vitest (component smoke tests)
```

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) — free for any **noncommercial**
purpose (evaluation, research, personal and nonprofit/government use). Commercial use is
not granted by this license.

**Commercial licensing:** a separate commercial license is available — contact
benwold@gmail.com.

**Contributions:** by submitting a contribution you agree it is licensed under the same
terms and that the maintainer may also license it commercially.
