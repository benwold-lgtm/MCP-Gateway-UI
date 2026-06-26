// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// App-facing types. The device/overview shapes are DERIVED from the gateway's OpenAPI
// contract (src/gateway.d.ts, produced by `npm run gen:types` from gateway.openapi.json),
// so a gateway API change surfaces as a TypeScript error here instead of silent drift.
import type { components } from "./gateway";

type Schemas = components["schemas"];

export type Device = Schemas["DeviceSummary"];
export type Overview = Schemas["OverviewResponse"];
export type Diagnostics = Schemas["DeviceDiagnostics"];

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
