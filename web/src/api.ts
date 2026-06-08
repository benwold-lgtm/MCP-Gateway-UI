// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Typed client to the BFF. Same-origin in production (nginx) and via Vite proxy in
// dev, so the session cookie is sent automatically with credentials: "include".
import type { Overview, Role } from "./types";

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
  registerDevice: (d: { hostname: string; base_url: string }) => req<unknown>("POST", "/api/devices", d),
  deleteDevice: (hostname: string) => req<unknown>("DELETE", `/api/devices/${hostname}`),
};
