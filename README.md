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
| `bff/` | FastAPI BFF — `auth` (login/logout/me), `api` (proxy: overview, devices, metrics summary; Prometheus/Loki stubs), session + role gating. Tests included. |
| `web/` | React + Vite + TypeScript SPA — login, device list + counts, admin register/remove. Typed client (`src/api.ts`) over the BFF. |
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
| `GATEWAY_API_TOKEN` | Admin-role gateway key (server-side only) |
| `UI_ADMIN_PASSWORD` / `UI_VIEWER_PASSWORD` | Login password → role (empty disables) |
| `SESSION_SECRET` | Signs the session cookie (`openssl rand -hex 32`) |
| `COOKIE_SECURE` | `true` behind TLS |
| `PROMETHEUS_URL` / `LOKI_URL` | Phase-2 monitoring sources |
| `CORS_ORIGINS` | Only needed if the SPA is served from a different origin than the BFF |

## Roadmap (phasing)

1. **Device management** (this scaffold) — list/register/remove over the gateway REST API, status from `/admin/overview`.
2. **Monitoring** — Prometheus panels (embed Grafana or render from the query API) + logs via Loki/Splunk, both proxied through the BFF.
3. **Live + RBAC-aware** — SSE/WS device status, per-role views, device detail + tool explorer.

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
