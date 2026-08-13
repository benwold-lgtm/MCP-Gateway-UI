// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Typed client to the BFF. Same-origin in production (nginx) and via Vite proxy in
// dev, so the session cookie is sent automatically with credentials: "include".
import type {
  AuthConfig,
  DeviceFull,
  DeviceMutation,
  DevicePayload,
  Diagnostics,
  Overview,
  Role,
  Session,
  ToolsDiff,
  ToolsResponse,
} from "./types";
import type { DeadLetterList, LokiResponse, MonitoringMeta, PromQueryResponse } from "./types";

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const resp = await fetch(path, {
    method,
    credentials: "include",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    const detail = await resp.json().catch(() => ({}));
    throw new ApiError(resp.status, (detail as { detail?: string }).detail ?? resp.statusText);
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
};
