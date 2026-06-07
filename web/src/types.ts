// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Mirrors the gateway's response shapes. Generate these from the gateway's
// /openapi.json (e.g. openapi-typescript) to keep them in lockstep over time.

export type Role = "admin" | "viewer";

export interface Device {
  hostname: string;
  base_url: string;
  transport: string;
  reachable: boolean;
  pod_active: boolean;
  last_check: number | null;
  rate_limit_rps: number | null;
}

export interface Overview {
  mode: string;
  counts: {
    total: number;
    active_pods: number;
    reachable: number;
    unreachable: number;
  };
  devices: Device[];
}
