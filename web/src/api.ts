// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Typed client to the BFF. Same-origin in production (nginx) and via Vite proxy in
// dev, so the session cookie is sent automatically with credentials: "include".
import type {
  DeviceFull,
  DevicePayload,
  Diagnostics,
  Overview,
  Role,
  ToolsDiff,
  ToolsResponse,
} from "./types";
import type { LokiResponse, MonitoringMeta, PromQueryResponse } from "./types";

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
  logout: () => req<{ status: string }>("POST", "/auth/logout"),
  me: () => req<{ role: Role }>("GET", "/auth/me"),
  overview: () => req<Overview>("GET", "/api/overview"),
  getDevice: (hostname: string) => req<DeviceFull>("GET", `/api/devices/${hostname}`),
  diagnostics: (hostname: string) => req<Diagnostics>("GET", `/api/devices/${hostname}/diagnostics`),
  tools: (hostname: string) => req<ToolsResponse>("GET", `/api/devices/${hostname}/tools`),
  toolsDiff: (hostname: string) => req<ToolsDiff>("GET", `/api/devices/${hostname}/tools/diff`),
  registerDevice: (d: DevicePayload) => req<unknown>("POST", "/api/devices", d),
  updateDevice: (hostname: string, d: DevicePayload) => req<unknown>("PUT", `/api/devices/${hostname}`, d),
  deleteDevice: (hostname: string) => req<unknown>("DELETE", `/api/devices/${hostname}`),
  // Monitoring (BFF-proxied Prometheus/Loki).
  monitoringMeta: () => req<MonitoringMeta>("GET", "/api/monitoring/meta"),
  prometheusQuery: (query: string) =>
    req<PromQueryResponse>("GET", `/api/prometheus/query?query=${encodeURIComponent(query)}`),
  logs: (limit = 100) => req<LokiResponse>("GET", `/api/logs?limit=${limit}`),
};
