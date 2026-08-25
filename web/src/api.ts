// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Typed client to the BFF. Same-origin in production (nginx) and via Vite proxy in
// dev, so the session cookie is sent automatically with credentials: "include".
import type {
  ActGrant,
  ArchiveKind,
  BackupPrepared,
  ActGrantResponse,
  AuthConfig,
  Elevation,
  ElevationResponse,
  Estate,
  ProviderScope,
  DeviceFull,
  DeviceMutation,
  DevicePayload,
  Diagnostics,
  InvokeEnvelope,
  OnConflict,
  Overview,
  RestoreReport,
  Role,
  Session,
  ToolsDiff,
  ToolsResponse,
} from "./types";
import type { DeadLetterList, LokiResponse, MonitoringMeta, PromQueryResponse } from "./types";

/** Almost every gateway/BFF error's `detail` is a plain string. `ERR_PLAN_STALE`
 *  (ADR-0018 §6) is the one exception: a dict carrying `message` alongside `error_code`
 *  and `fields`, so a caller can act on the code without parsing the sentence. Without
 *  this, that dict would reach `ApiError`'s message unstringified and render as
 *  "[object Object]" at the operator instead of the sentence telling them what to do. */
function errorMessage(detail: unknown): string | undefined {
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object" && typeof (detail as { message?: unknown }).message === "string") {
    return (detail as { message: string }).message;
  }
  return undefined;
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const resp = await fetch(path, {
    method,
    credentials: "include",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new ApiError(resp.status, errorMessage((body as { detail?: unknown }).detail) ?? resp.statusText);
  }
  return (await resp.json()) as T;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export const api = {
  login: (password: string) => req<{ role: Role }>("POST", "/auth/login", { password }),
  logout: () => req<{ status: string; end_session_url?: string | null }>("POST", "/auth/logout"),
  me: () => req<Session>("GET", "/auth/me"),
  authConfig: () => req<AuthConfig>("GET", "/auth/config"),
  overview: () => req<Overview>("GET", "/api/overview"),
  getDevice: (hostname: string) => req<DeviceFull>("GET", `/api/devices/${hostname}`),
  diagnostics: (hostname: string) => req<Diagnostics>("GET", `/api/devices/${hostname}/diagnostics`),
  tools: (hostname: string) => req<ToolsResponse>("GET", `/api/devices/${hostname}/tools`),
  toolsDiff: (hostname: string) => req<ToolsDiff>("GET", `/api/devices/${hostname}/tools/diff`),
  // --- backup / restore (ADR-0011) -------------------------------------------
  // Step one of two. Mints the archive, stages it on the session for 120s and returns the
  // passphrase once. Deliberately not the file: see `downloadBackupUrl`.
  prepareBackup: (body: { kind: ArchiveKind; passphrase?: string; include_deadletters?: boolean }) =>
    req<BackupPrepared>("POST", "/api/admin/backup", body),
  // Step two, and NOT a `req` call: the browser must fetch this itself so the response
  // becomes a native download. Same-origin and cookie-authenticated, so a plain navigation
  // carries the session. The token is claimed before the body is served, so this works once.
  downloadBackupUrl: (token: string) => `/api/admin/backup/download?token=${encodeURIComponent(token)}`,
  // `dry_run` is required rather than defaulted here even though the BFF and the gateway both
  // default it to true. Three layers each quietly defaulting is how the destructive direction
  // eventually becomes reachable by omission; at the call site it has to be typed out.
  // `plan_token` is required by the gateway on `dry_run: false` (ADR-0018 §6) — the token a
  // preceding preview of this exact request returned — but stays optional in the type: a
  // preview call never has one to send, and a caller sending an apply without one gets the
  // gateway's own `plan_token is required` 400 rather than a client-side one duplicating it.
  restore: (body: {
    archive: unknown;
    passphrase?: string;
    dry_run: boolean;
    on_conflict: OnConflict;
    include_deadletters?: boolean;
    plan_token?: string;
  }) => req<RestoreReport>("POST", "/api/admin/restore", body),
  // One call, three upstream hops (initialize / tools/call / delete) that the BFF runs on our
  // behalf — a bare `tools/call` cannot be forwarded through the MCP transport. Resolves with
  // the JSON-RPC envelope on HTTP 200 whether the call succeeded or was refused; it rejects
  // only for transport- and authorization-level failures (403 without a live elevation, 409
  // with no active pod).
  invokeTool: (hostname: string, tool: string, args: Record<string, unknown>) =>
    req<InvokeEnvelope>("POST", `/api/devices/${hostname}/tools/${encodeURIComponent(tool)}/invoke`, {
      arguments: args,
    }),
  registerDevice: (d: DevicePayload) => req<unknown>("POST", "/api/devices", d),
  updateDevice: (hostname: string, d: DevicePayload) => req<unknown>("PUT", `/api/devices/${hostname}`, d),
  deleteDevice: (hostname: string) => req<unknown>("DELETE", `/api/devices/${hostname}`),
  // Re-pin a device to the key it is now presenting (gateway ADR-0015 §6). Admin-only at
  // the BFF; the gateway 409s when the device is not actually pending approval.
  approveFingerprint: (hostname: string) =>
    req<DeviceMutation>("POST", `/api/devices/${hostname}/fingerprint/approve`),
  // Dead-letter queue (gateway F-10, distributed mode). `ids` selects specific
  // entries; omit to act on the whole batch.
  deadLetters: (hostname: string) => req<DeadLetterList>("GET", `/api/devices/${hostname}/deadletter`),
  replayDeadLetters: (hostname: string, ids?: string[]) =>
    req<{ replayed: number }>(
      "POST",
      `/api/devices/${hostname}/deadletter/replay`,
      ids ? { ids } : undefined,
    ),
  drainDeadLetters: (hostname: string, ids?: string[]) =>
    req<{ removed: number }>("DELETE", `/api/devices/${hostname}/deadletter`, ids ? { ids } : undefined),
  // Monitoring (BFF-proxied Prometheus/Loki).
  monitoringMeta: () => req<MonitoringMeta>("GET", "/api/monitoring/meta"),
  prometheusQuery: (query: string) =>
    req<PromQueryResponse>("GET", `/api/prometheus/query?query=${encodeURIComponent(query)}`),
  logs: (limit = 100) => req<LokiResponse>("GET", `/api/logs?limit=${limit}`),

  // --- provider plane (ADR-0013 §4/§8) ---------------------------------------
  // These live under /provider, not /api: a different plane with a different session
  // vocabulary, and the BFF refuses them outright for a tenant session.
  provider: {
    // §8's "renewal is a new act, not an extension" — this always mints, so the UI must
    // never call it to top up a countdown. Re-authorizing is a fresh act with a fresh
    // justification and its own audit record.
    authorize: (tenant: string, justification: string) =>
      req<ActGrant>("POST", `/provider/tenants/${encodeURIComponent(tenant)}/authorize`, { justification }),
    // The estate + what this console serves. Navigation only — posting a tenant that is
    // not in the list is still accepted here and still judged by the gateway (§11c).
    tenants: () => req<Estate>("GET", "/provider/tenants"),
    actOnTenant: () => req<ActGrantResponse>("GET", "/provider/act-on-tenant"),
    release: () => req<{ released: string | null }>("DELETE", "/provider/act-on-tenant"),
    // Returns the IdP URL to navigate to — not a grant. Nothing is authorized until the
    // browser comes back through the step-up callback and the `acr` is verified there.
    elevate: (tenant: string, scope: ProviderScope, justification: string) =>
      req<{ authorization_url: string }>("POST", `/provider/tenants/${encodeURIComponent(tenant)}/elevate`, {
        scope,
        justification,
      }),
    elevation: () => req<ElevationResponse>("GET", "/provider/elevation"),
    endElevation: () => req<{ released: string | null }>("DELETE", "/provider/elevation"),
  },
};

// Narrowing helpers for the two null-sentinel responses, so views read a grant or `null`
// rather than repeating the shape check.
export const asGrant = (r: ActGrantResponse): ActGrant | null => ("grant" in r ? null : r);
export const asElevation = (r: ElevationResponse): Elevation | null => ("elevation" in r ? null : r);
