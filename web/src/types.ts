// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// App-facing types. The device/overview shapes are DERIVED from the gateway's OpenAPI
// contract (src/gateway.d.ts, produced by `npm run gen:types` from gateway.openapi.json),
// so a gateway API change surfaces as a TypeScript error here instead of silent drift.
import type { components } from "./gateway";

type Schemas = components["schemas"];

export type Device = Schemas["DeviceSummary"];
export type DeviceFull = Schemas["DeviceDetail"];
export type Overview = Schemas["OverviewResponse"];
// What a device write returns: the envelope plus the resulting device.
export type DeviceMutation = Schemas["DeviceMutationResult"];
export type Diagnostics = Schemas["DeviceDiagnostics"];
export type ToolsDiff = Schemas["ToolsDiffResponse"];

// Register/update request body. The gateway's POST/PUT body has no named OpenAPI
// schema, so it's declared here. PUT preserves any field that is omitted (including
// `auth`, which keeps the stored credentials).
export type ApiKeyAuth = { api_key: string; location?: string; name?: string; value_prefix?: string };
export type OAuth2Auth = {
  token_endpoint: string;
  client_id: string;
  client_secret: string;
  scopes?: string[];
};
export type DevicePayload = {
  hostname?: string;
  base_url?: string;
  spec_url?: string;
  transport?: string;
  rate_limit_rps?: number;
  auth_type?: "none" | "api_key" | "oauth2";
  auth?: ApiKeyAuth | OAuth2Auth;
};

// The gateway's GET /devices/{h}/tools has no response model (it returns a plain
// dict), so this shape is declared here rather than derived from the OpenAPI. Keep
// it in sync with the gateway's tool dict in main.py's get_device_tools.
export type Tool = {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  method: string;
  path: string;
};
export type ToolsResponse = { hostname: string; tools: Tool[]; count: number };

// What `POST /api/devices/{h}/tools/{t}/invoke` answers with: the gateway's JSON-RPC envelope,
// passed through untouched. Note it arrives over **HTTP 200 even when the call was refused** —
// a JSON-RPC error is a body, not a status — so callers must read the envelope rather than the
// response code. `readOutcome` in `toolArgs.ts` is the only place that should do that.
export type InvokeEnvelope = {
  jsonrpc?: string;
  id?: number | string;
  result?: {
    content?: { type?: string; text?: string }[];
    structuredContent?: unknown;
    isError?: boolean;
  };
  error?: { code?: number; message?: string; data?: unknown };
};

// UI-local — the role comes from the BFF session, not the gateway response contract.
export type Role = "admin" | "viewer";

// Gateway scope strings (ADR-0007). The UI gates affordances on scopes, not roles, so it
// tracks the gateway's authorization for both password and OIDC sessions.
export type Scope = "devices:read" | "devices:write" | "tools:call" | "metrics:read";

// Provider-plane scopes (ADR-0013 §5). A SEPARATE vocabulary from `Scope` above, and kept
// separate in the type system for the same reason /auth/me reports them in their own field:
// they are not gateway scopes, the gateway has never heard of them, and a union of the two
// would let a view gate a tenant affordance on provider authority or the reverse.
export type ProviderScope = "provider:monitor" | "provider:admin" | "provider:invoke";

// Which plane authenticated this session. A fact about which IdP was used, never a
// selector the browser sends.
export type Plane = "tenant" | "provider";

// The signed-in session as reported by the BFF /auth/me.
export type Session = {
  kind: "password" | "oidc";
  plane: Plane;
  subject: string;
  role: Role | null;
  // For OIDC the BFF relays whatever scopes the gateway grants, which may include strings
  // outside the known union — so accept extra strings rather than over-narrowing.
  scopes: (Scope | string)[];
  // Always present, always `[]` on the tenant plane — the BFF states it rather than
  // omitting it so a missing key never has to be read as "unknown".
  provider_scopes: (ProviderScope | string)[];
  name?: string | null;
};

// What login methods the BFF offers (GET /auth/config). `provider_enabled` says which
// console this deployment IS, not which one to offer: the BFF refuses to start carrying
// both IdPs (§2/§5), so it is never true alongside `oidc_enabled`.
export type AuthConfig = {
  oidc_enabled: boolean;
  password_login: boolean;
  provider_enabled: boolean;
  step_up_enabled: boolean;
};

// --- the provider plane (ADR-0013 §4/§8) -------------------------------------

// A live act-on-tenant grant (GET/POST /provider/...). The justification is deliberately
// NOT echoed back by the BFF — it is evidence, already in the audit chain.
export type ActGrant = {
  id: string;
  tenant: string;
  granted_at: number;
  expires_at: number;
};

// A live elevation on top of the act. `single_use` is currently always false — the one
// remaining class (`provider:invoke`) isn't single-use — but the field stays: it's what
// would make a future single-use class visibly different, and it is rendered, not just
// carried, for that reason.
export type Elevation = {
  id: string;
  tenant: string;
  scope: ProviderScope | string;
  granted_at: number;
  expires_at: number;
  single_use: boolean;
};

// The estate (GET /provider/tenants). Two facts that must not be merged:
//
//   `entitled` — what the directory said at login. `null` means the IdP published no list
//                (a mapper is missing); `[]` means it published an empty one. Different
//                situations with different remedies, so the union keeps them apart and the
//                console renders a different sentence for each.
//   `served`   — the single tenant this console's gateway *is*. Every other entitled tenant
//                is a legitimate act that currently reaches no devices (slice 3).
//
// Neither field authorizes anything: ADR-0013 §11c puts the intersection on the gateway,
// because the console is the side that chose the tenant.
export type Estate = {
  entitled: string[] | null;
  served: string | null;
};

// The two endpoints above answer with a null sentinel rather than 404 when nothing is
// held, so "no grant" is a value the caller reads instead of an error it has to catch.
export type ActGrantResponse = ActGrant | { grant: null };
export type ElevationResponse = Elevation | { elevation: null };

// How a step-up came back, read from the query string the BFF redirected to. The reason
// vocabulary is closed on the BFF side (STEP_UP_* in routers/auth.py).
export type StepUpOutcome =
  | { status: "granted" }
  | {
      status: "denied";
      reason:
        | "invalid_callback"
        | "state_mismatch"
        | "token_exchange_failed"
        | "step_up_declined"
        | "grant_refused"
        | string;
    };

// Monitoring — the BFF's /monitoring/meta plus the Prometheus/Loki proxy responses.
// No gateway OpenAPI schema backs these (they describe external systems), so they
// are declared here.
export type MonitoringMeta = {
  prometheus_enabled: boolean;
  loki_enabled: boolean;
  grafana_url: string | null;
};
export type PromResult = { metric: Record<string, string>; value: [number, string] };
export type PromQueryResponse = { status: string; data: { resultType: string; result: PromResult[] } };
export type LokiStream = { stream: Record<string, string>; values: [string, string][] };
export type LokiResponse = { status: string; data: { resultType: string; result: LokiStream[] } };

// Dead-letter queue (gateway F-10, distributed mode). The DLQ response has no named
// gateway OpenAPI schema, so the entry shape is declared here.
export type DeadLetterEntry = {
  id: string;
  reason: string;
  ts: string;
  method: string | null;
  rid: string;
  request_id: string;
  session_id: string;
};
export type DeadLetterList = { hostname: string; count: number; entries: DeadLetterEntry[] };

// --- Backup and restore (ADR-0011, ADR-0013 §5b/§8) ---------------------------

/** `ciphertext` restores into this stack or any sharing its `MCP_SECRET_KEY`; `portable`
 *  crosses key generations and is sealed under a passphrase instead. Both are complete
 *  credential dumps for anyone holding the corresponding secret — the console says so. */
export type ArchiveKind = "ciphertext" | "portable";

/** What a restore does with a hostname that is already registered. */
export type OnConflict = "skip" | "overwrite" | "fail";

/** First leg of the two-step export. Carries **no archive** — a native browser download
 *  cannot read the header the passphrase arrives in, so the file is fetched separately with
 *  `download_token`. `passphrase` is non-null only when the gateway minted one, and this is
 *  the only time it is ever sent. */
export type BackupPrepared = {
  download_token: string;
  filename: string;
  expires_at: number;
  passphrase: string | null;
};

/** One device's predicted or actual fate. `would_restore` appears only in a dry run.
 *
 * ⚠️ **Hand-maintained.** The gateway's restore route returns a plain dict with no OpenAPI
 * schema, so unlike `Device`/`Overview` this shape is not generated and `check:spec` cannot
 * see it drift. When the gateway's restore report changes, it changes here by hand or not at
 * all — which is how the `*_needs_reconnect` outcomes below arrived unrendered.
 */
export type RestoreDeviceResult = {
  hostname: string;
  outcome:
    | "restored"
    | "would_restore"
    /** Restored, and **cannot authenticate**: its OAuth2 refresh token is excluded from every
     *  archive (gateway ADR-0018 §3) and that token was the credential. A human must
     *  re-authorize it. Not a failure — the device is registered and may be reachable. */
    | "restored_needs_reconnect"
    | "would_restore_needs_reconnect"
    | "skipped"
    | "failed";
  reason?: string;
  /** Set when the restore would discard an archived fingerprint pin or leave a device to
   *  trust-on-first-use. Surfaced by the gateway at the top level too, because on a large
   *  fleet this is exactly what gets missed inside a per-device list. */
  fingerprint_warning?: string;
  /** Set when **this stack** cannot resolve the device's `credential_ref` — the secret is not
   *  in this store. The device restores anyway; provisioning the secret is a separate
   *  operation (ADR-0018 §2a). Absent when the fault is the store itself, which is reported
   *  once at the top instead — see `credential_store_error`. */
  credential_warning?: string;
};

export type RestoreReport = {
  dry_run: boolean;
  kind: ArchiveKind | string;
  on_conflict: OnConflict | string;
  created_at?: string | null;
  counts: Record<string, number>;
  fingerprint_warnings: number;
  /** Optional because a gateway older than ADR-0018 §3 does not send them. Treated as 0 /
   *  absent rather than assumed present — the console must not blank out against an older
   *  gateway it is otherwise compatible with. */
  needs_reconnect?: number;
  credential_warnings?: number;
  /** The **fleet-level** credential fault: the secret store is unusable on this stack, or
   *  none is configured. Its presence means per-device credential results were deliberately
   *  not produced (ADR-0018 §7) — one mount is wrong, not N references. */
  credential_store_error?: string | null;
  devices: RestoreDeviceResult[];
  /** RFC 8785 canonical-JSON digest of the exact inputs that produced this report (gateway
   *  ADR-0018 §6). Carried on both a preview and its apply. Optional for the same reason as
   *  the credential fields above: a gateway older than §6 does not send it. */
  plan_digest?: string;
  /** Only on a preview, and only from a gateway new enough to send `plan_digest` at all.
   *  An HMAC-signed token committing to it; submit it back on the next call with
   *  `dry_run: false` to apply exactly this plan — the gateway refuses a missing, forged,
   *  or stale one as `ERR_PLAN_STALE` before writing anything. Absent on an applied report:
   *  an apply consumes a token, it does not mint one. */
  plan_token?: string;
};

// --- catalog (ADR-0020, provider plane) ----------------------------------------------
// Hand-written rather than `Schemas[...]`-derived: these describe the catalog service's own
// contract (device_mcp_catalog/), a separate OpenAPI document from the gateway's, and
// generating types from a second spec is out of scope for this slice.

export type UpstreamKind = "openapi" | "mcp";
export type AuthKind = "none" | "api_key" | "oauth2";
export type FingerprintPolicy = "warn" | "enforce";

export type DeviceTypeVersion = {
  id: string;
  device_type_id: string;
  version: number;
  transport: string;
  upstream_kind: UpstreamKind;
  upstream_transport: "http" | "sse";
  /** Relative to whatever base_url a tenant supplies at claim time — never an absolute URL. */
  spec_path?: string | null;
  auth_kind: AuthKind;
  fingerprint_policy?: FingerprintPolicy | null;
  changelog?: string | null;
  created_at: string;
};

export type DeviceType = {
  id: string;
  slug: string;
  name: string;
  description?: string | null;
  created_at: string;
  latest_version: number;
};

export type DeviceTypeDetail = DeviceType & { versions: DeviceTypeVersion[] };

export type DeviceTypeListResponse = { device_types: DeviceType[] };

export type Assignment = {
  id: string;
  device_type_id: string;
  tenant_id: string;
  assigned_at: string;
  assigned_by: string;
  revoked_at?: string | null;
};
