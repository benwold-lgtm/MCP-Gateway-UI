# Changelog

All notable changes to the SyncGate console (BFF + SPA) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, **minor releases may include breaking changes.**

> **This file starts at 0.2.0.** The console had no changelog for its first two versions,
> and 57 pull requests landed between v0.1.1 (2026-07-06) and this release. Reconstructing
> a per-change record for all of them after the fact would produce something less accurate
> than the git history it was derived from, so 0.2.0 is written as a **summary by theme**
> and `git log v0.1.1..v0.2.0` remains the detailed record. Later releases are recorded
> as they happen.

## [0.2.0] - 2026-09-02

Requires gateway **0.3.6**. The console tracks the gateway's contract, and this release is
the first to be published against a gateway with the split restore routes — an older
console posts to `POST /v1/admin/restore`, which no longer exists.

### Added

- **The provider plane, and then a decision to freeze it.** A second console with its own
  IdP, plane-aware sessions that cannot be confused for tenant ones, the device catalog
  (curation, assignment, the tenant claim flow, upgrade offers), and both halves of the
  ADR-0024 enrolment handshake. The provider tier is now **frozen** — lite and single-tenant
  are the supported editions — so these screens are present but the tier is not being
  developed. Nothing is deleted.

- **Delegated support (ADR-0017).** A tenant admin sees pending requests, who can currently
  reach their stack, and standing consent; a provider raises a request rather than holding
  standing access. The act-on-tenant/elevated-grant mechanism that preceded it was removed
  rather than kept alongside.

- **Backup and restore in the tenant console** (ADR-0011). The routes were always mounted on
  both planes; only the screen was missing, so the capability was reachable with `curl`
  while the console implied it was not. Two-step export: prepare, then claim the file.

- **Tool invocation** from a device's tool list, gated on `tools:call` rather than on a role.

- **Registering an MCP server** (ADR-0009). The form branches on `upstream_kind`, so the
  product's headline upstream type is reachable without hand-writing an API call.

- **ADR-0015 §8's TLS pre-pin at registration, and the per-device fingerprint policy**, the
  latter editable on an existing device from 0.3.6.

- **`credential_state` on the device list** — a device that is reachable, running, and
  cannot authenticate is a state an operator scans a list for.

- **A design pass**: an application shell, a three-state health vocabulary, one palette
  across both portals, a shipped typeface, and measured contrast.

### Fixed

- **No OpenAPI device type had ever been claimable** (LR-48). The claim path sent
  `upstream_transport` on every registration, and the gateway refuses that key on an OpenAPI
  device *on the presence of the key* — so the catalog's own default of `"http"` was rejected
  as though it were a wrong value. Live since 2026-08-11 and green in both test suites,
  because each was asserted against its own double. The fix that matters is not the one line:
  **`bff/tests/gateway_contract.py`** is a fake gateway that refuses what the real one
  refuses, and `contract/console-device-registration.json` holds the request bodies both
  suites assert against, so the browser plane and the server plane can no longer agree with
  each other while disagreeing with the gateway.

- **Two OIDC issuer defects** (TM-I-05): the BFF trusted the discovery document's own
  `jwks_uri` rather than pinning the issuer to config, and accepted a plaintext `http://`
  issuer without an explicit opt-in.

- **A widened session cookie is refused at startup** (C8). A cookie on `.example.com` is sent
  to every tenant console beneath it, so one tenant's browser would carry a session into
  another's portal with nothing appearing to break.

- **Rate limiting throttled the ingress, not the caller** — `X-Forwarded-For` was read from
  the wrong end, and trust was expressed as a hop count rather than as proxy ranges.

- **A trailing newline in a secret made break-glass login impossible.**

- **Screens that could only ever be empty are no longer shown.** On a Lite or single-tenant
  stack: no "Claim from catalog" button (the route 503s without a `TENANT_ID`), no catalog
  upgrade poll on every devices-view load, and no Support tab — that last one gated on the
  *live* enrolment list as well as on config, because the support routes need no `TENANT_ID`
  of their own and an enrolment can outlive the setting. Withholding the tab on config alone
  would remove the only control that can end a provider's access while leaving the access
  standing.

- **Monitoring works without a Prometheus.** Two of the four tiles are registry facts the
  gateway already publishes, so a deployment with no `PROMETHEUS_URL` gets live counts
  instead of a sentence naming an environment variable. The copy states what they are not:
  instantaneous, no history, and two of the four Prometheus metrics genuinely absent.

- **The vendored gateway contract had drifted 16 paths** — 22 where the gateway serves 37,
  missing both restore routes and every enrolment/support route, still carrying a
  `/v1/admin/restore` that no longer exists. `check:spec` never caught it because it only
  runs when a reference spec is configured, which is exactly what its own header warns about.

### Changed

- **Renamed.** `MCP-Gateway-UI` is now `SyncGate-UI`, and the console reads *SyncGate*.
  GitHub redirects the old paths.

- **Lite moved out.** The lite compose file and its guide now live in
  [SyncGate-Lite](https://github.com/benwold-lgtm/SyncGate-Lite). This repo still builds the
  images Lite runs.

[0.2.0]: https://github.com/benwold-lgtm/SyncGate-UI/releases/tag/v0.2.0
