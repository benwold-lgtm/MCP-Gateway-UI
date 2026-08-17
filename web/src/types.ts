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
export type ProviderScope =
  | "provider:monitor"
  | "provider:admin"
  | "provider:invoke"
  | "provider:credentials";

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

// A live elevation on top of the act. `single_use` is what makes a credentials grant
// visibly different from an invoke one, so it is rendered, not just carried.
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
