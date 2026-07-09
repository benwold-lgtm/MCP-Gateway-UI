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
| `bff/` | FastAPI BFF — `auth` (login/logout/me), `api` (proxy: overview, device CRUD incl. `PUT`, per-device diagnostics + tools, dead-letter inspect/replay/drain, metrics summary, Prometheus/Loki + monitoring meta), session + role gating. Tests included. |
| `web/` | React + Vite + TypeScript SPA — login, device list + counts, a **full register/edit form** (auth `api_key`/`oauth2`, `spec_url`, rate limit; create via `POST`, edit via `PUT`), remove, a **device-detail panel** (diagnostics + tool explorer + dead-letter queue), and a **Monitoring view** (critical-metric tiles + central-monitoring pointers + recent logs). Typed client (`src/api.ts`) over the BFF. |
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
| `GATEWAY_API_TOKEN` | Admin-role gateway key (server-side only); used for local password sessions and as break-glass |
| `UI_ADMIN_PASSWORD` / `UI_VIEWER_PASSWORD` | Local break-glass login password → role (empty disables) |
| `SESSION_SECRET` | Signs the session-id cookie and the OIDC login transaction (`openssl rand -hex 32`). The BFF **refuses to start** with the default value when `COOKIE_SECURE=true` |
| `SESSION_REDIS_URL` | Shared server-side session store. **Required for >1 BFF replica** (the K8s overlay runs 2 — no session affinity); empty = in-memory store, right for a single replica |
| `SESSION_TTL_SECONDS` | Server-side session lifetime (default `28800` = 8 h) |
| `COOKIE_SECURE` | `true` behind TLS |
| `LOGIN_MAX_FAILURES` / `LOGIN_WINDOW_SECONDS` | Break-glass password throttle: after this many failed attempts from one client IP within the window, further attempts get `429` until it rolls off (defaults `5` / `60`) |
| `TRUST_FORWARDED_FOR` | `true` only when the BFF is behind a proxy that sets `X-Forwarded-For`, so the throttle keys on the real client IP rather than the proxy (default `false` — otherwise the header is spoofable) |
| `OIDC_ENABLED` | Turn on federated SSO (Authorization Code + PKCE). See **Federated identity** below |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | IdP issuer URL + client credentials (omit the secret for a public/PKCE-only client) |
| `OIDC_REDIRECT_URL` | This BFF's callback, registered with the IdP (`…/auth/oidc/callback`) |
| `OIDC_SCOPES` / `OIDC_POST_LOGIN_REDIRECT` | Requested scopes (include one yielding a gateway-audience access token; defaults include `offline_access` so the IdP issues a refresh token for silent refresh — drop it if your IdP rejects it) / where to land after login |
| `OIDC_POST_LOGOUT_REDIRECT` | Where the IdP returns the browser after RP-initiated (single) logout; must be registered with the IdP. Empty = omit. Used only if the IdP exposes an `end_session_endpoint` |
| `PROMETHEUS_URL` / `LOKI_URL` | Monitoring sources, proxied by the BFF for the Monitoring view (critical-metric tiles / recent logs). Empty = lean on central monitoring |
| `GRAFANA_URL` | Optional link to central Grafana, surfaced in the Monitoring view |
| `CORS_ORIGINS` | Only needed if the SPA is served from a different origin than the BFF |

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
- **password** — the existing local **break-glass / bootstrap** login. It proxies upstream
  with the single admin `GATEWAY_API_TOKEN`, so the BFF still enforces the admin/viewer role.
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
7. **Live** — SSE/WS device status, finer per-scope views.

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
gateway and it diffs the committed snapshot's path/version surface, failing on drift.

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
