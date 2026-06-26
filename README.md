# Device MCP Gateway — UI

A **separate, optional** management UI for the [Device MCP Gateway](../device-mcp-gateway).
Deployed independently; the gateway has **no dependency** on it (it only added a small
aggregate endpoint, `GET /admin/overview`). This is a **starter scaffold** (F14) — minimal
but real structure to build on.

## Architecture — thin BFF + SPA

```
  Browser (SPA: React + Vite + TS)
      │  signed session cookie (opaque; no gateway token in the browser)
      ▼
  BFF (FastAPI)  ── holds the gateway admin token, runs the session, authorizes by role
      │
      ├──► Gateway API        (device CRUD, /admin/overview, /metrics/summary)
      ├──► Prometheus query    (phase 2 — monitoring panels)
      └──► Loki / Splunk query (phase 2 — logs; the gateway is never in the log path)
```

**Why a BFF?** The browser must never hold the gateway admin credential. The BFF keeps it
server-side, exposes only an opaque signed-cookie session, maps that session to a role
(`admin`/`viewer`, mirroring the gateway's RBAC), and proxies allowed calls upstream.

## What's in the scaffold

| Path | What |
|------|------|
| `bff/` | FastAPI BFF — `auth` (login/logout/me), `api` (proxy: overview, device CRUD incl. `PUT`, per-device diagnostics + tools, metrics summary, Prometheus/Loki + monitoring meta), session + role gating. Tests included. |
| `web/` | React + Vite + TypeScript SPA — login, device list + counts, a **full register/edit form** (auth `api_key`/`oauth2`, `spec_url`, rate limit; create via `POST`, edit via `PUT`), remove, a **device-detail panel** (diagnostics + tool explorer), and a **Monitoring view** (critical-metric tiles + central-monitoring pointers + recent logs). Typed client (`src/api.ts`) over the BFF. |
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

## Configuration (BFF env)

| Var | Purpose |
|-----|---------|
| `GATEWAY_URL` | Gateway API base URL |
| `GATEWAY_API_PREFIX` | Gateway management-API version prefix (default `/v1`; change only for a future `/v2`) |
| `GATEWAY_API_TOKEN` | Admin-role gateway key (server-side only) |
| `UI_ADMIN_PASSWORD` / `UI_VIEWER_PASSWORD` | Login password → role (empty disables) |
| `SESSION_SECRET` | Signs the session cookie (`openssl rand -hex 32`) |
| `COOKIE_SECURE` | `true` behind TLS |
| `PROMETHEUS_URL` / `LOKI_URL` | Monitoring sources, proxied by the BFF for the Monitoring view (critical-metric tiles / recent logs). Empty = lean on central monitoring |
| `GRAFANA_URL` | Optional link to central Grafana, surfaced in the Monitoring view |
| `CORS_ORIGINS` | Only needed if the SPA is served from a different origin than the BFF |

## Roadmap (phasing)

1. **Device management** (this scaffold) — list/remove over the gateway REST API, status from `/admin/overview`.
2. **Device detail** ✅ — per-device diagnostics ("why is my device down?"), a tool explorer (the generated MCP tools + their input schemas), and a **recent tool-set change** panel (added/removed/changed + breaking flag), from `/devices/{h}/diagnostics`, `/devices/{h}/tools`, and `/devices/{h}/tools/diff`.
3. **Register / edit** ✅ — a full create + edit form (auth `api_key`/`oauth2`, `spec_url`, rate limit), `POST` to register and `PUT` to edit; edit pre-fills from the gateway and omits `auth` by default so stored credentials are preserved.
4. **Monitoring** ✅ (metrics + logs) — a lightweight native view: critical at-a-glance metric tiles (Prometheus instant queries) + a recent-logs panel (Loki LogQL), both proxied through the BFF, plus first-class pointers to **central monitoring** (the gateway's `:9100/metrics` scrape endpoint and an optional Grafana link). Intentionally not a full monitoring app. **DLQ inspect/replay/drain is the remaining piece of this phase.**
5. **Live + RBAC-aware** — SSE/WS device status, per-role views, login throttling + per-user identity.

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
