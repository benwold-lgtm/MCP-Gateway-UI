// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Typed client to the BFF. Same-origin in production (nginx) and via Vite proxy in
// dev, so the session cookie is sent automatically with credentials: "include".
import type {
  ArchiveKind,
  Assignment,
  BackupPrepared,
  AuthConfig,
  ClaimPayload,
  DeviceTypeDetail,
  DeviceTypeListResponse,
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
  UpgradeOffersResponse,
  UpstreamKind,
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
  // 204 (the catalog revoke route, ADR-0020 §2) has no body to parse — by definition,
  // not by omission — so this returns before the .json() call every other success path
  // still makes.
  if (resp.status === 204) return undefined as T;
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
  // --- claim from catalog (ADR-0020 §4, tenant plane) -------------------------------
  // This tenant's currently assigned device types — what the catalog claim view lists.
  // Does not touch or gate registerDevice above: free-type registration keeps working
  // exactly as it does today.
  catalog: {
    listAssigned: () => req<DeviceTypeListResponse>("GET", "/api/catalog/device-types"),
    getDeviceType: (id: string) => req<DeviceTypeDetail>("GET", `/api/catalog/device-types/${id}`),
    // The BFF merges this with the type's current curated version and registers the
    // result via the gateway's ordinary devices route — the browser supplies only its
    // own half (host + credential), never the template fields.
    claim: (typeId: string, body: ClaimPayload) =>
      req<DeviceMutation>("POST", `/api/catalog/${typeId}/claim`, body),
    upgrades: () => req<UpgradeOffersResponse>("GET", "/api/catalog/upgrades"),
    // Never blocking, never scheduled, never forced (ADR-0020 §4). Re-pins this hostname
    // to the new version on the catalog side only — no gateway call, no change to the
    // live device.
    acceptUpgrade: (hostname: string, deviceTypeId: string, version: number) =>
      req<unknown>("POST", `/api/catalog/upgrades/${hostname}/accept`, {
        device_type_id: deviceTypeId,
        version,
      }),
  },
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

  // --- provider plane (ADR-0013 §2, catalog only as of ADR-0017 slice 6) -----
  // These live under /provider, not /api: a different plane with a different session
  // vocabulary, and the BFF refuses them outright for a tenant session.
  //
  // The act-on-tenant/elevated-grant methods that used to live here (`authorize`,
  // `tenants`, `actOnTenant`, `release`, `elevate`, `elevation`, `endElevation`) are
  // removed along with the mechanism they called (ADR-0017 slice 6 — `grants.py`,
  // `routers/provider.py` deleted). ADR-0017's replacement (slice 7) has a different
  // shape and will need its own methods, not a renaming of these.
  provider: {
    // --- catalog curation + assignment (ADR-0020 §1/§2) ------------------------
    // Not gated on a live act-on-tenant grant: curating the catalog and assigning a type
    // to a tenant are provider-plane acts on the provider's OWN storage (ADR-0020 §2),
    // never a write into any tenant's registry — so unlike Devices/Monitoring/Backup
    // above, this rail entry needs no act.
    catalog: {
      listDeviceTypes: () => req<DeviceTypeListResponse>("GET", "/provider/catalog/device-types"),
      getDeviceType: (id: string) => req<DeviceTypeDetail>("GET", `/provider/catalog/device-types/${id}`),
      createDeviceType: (body: {
        slug: string;
        name: string;
        description?: string;
        upstream_kind: UpstreamKind;
        spec_path?: string;
      }) => req<DeviceTypeDetail>("POST", "/provider/catalog/device-types", body),
      addVersion: (
        id: string,
        body: { upstream_kind: UpstreamKind; spec_path?: string; changelog?: string },
      ) => req<unknown>("POST", `/provider/catalog/device-types/${id}/versions`, body),
      // `assigned_by` is not part of this body — the BFF fills it in from the session's
      // own subject, never from what the browser sends (see routers/catalog.py).
      assign: (typeId: string, tenantId: string) =>
        req<Assignment>("POST", `/provider/catalog/device-types/${typeId}/assign`, { tenant_id: tenantId }),
      revoke: (typeId: string, tenantId: string) =>
        req<unknown>("DELETE", `/provider/catalog/device-types/${typeId}/assign/${tenantId}`),
    },
  },
};
