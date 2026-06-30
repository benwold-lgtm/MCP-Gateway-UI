// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// App-facing types. The device/overview shapes are DERIVED from the gateway's OpenAPI
// contract (src/gateway.d.ts, produced by `npm run gen:types` from gateway.openapi.json),
// so a gateway API change surfaces as a TypeScript error here instead of silent drift.
import type { components } from "./gateway";

type Schemas = components["schemas"];

export type Device = Schemas["DeviceSummary"];
export type DeviceFull = Schemas["DeviceDetail"];
export type Overview = Schemas["OverviewResponse"];
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

// UI-local — the role comes from the BFF session, not the gateway response contract.
export type Role = "admin" | "viewer";

// Gateway scope strings (ADR-0007). The UI gates affordances on scopes, not roles, so it
// tracks the gateway's authorization for both password and OIDC sessions.
export type Scope = "devices:read" | "devices:write" | "tools:call" | "metrics:read";

// The signed-in session as reported by the BFF /auth/me.
export type Session = {
  kind: "password" | "oidc";
  subject: string;
  role: Role | null;
  // For OIDC the BFF relays whatever scopes the gateway grants, which may include strings
  // outside the known union — so accept extra strings rather than over-narrowing.
  scopes: (Scope | string)[];
  name?: string | null;
};

// What login methods the BFF offers (GET /auth/config).
export type AuthConfig = { oidc_enabled: boolean; password_login: boolean };

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
