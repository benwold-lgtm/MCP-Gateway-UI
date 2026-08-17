// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import type { Device, Overview } from "../types";
import { api } from "../api";
import { deviceHealth, freshness, ui } from "../tokens";
import { HealthDot } from "./Health";

export function DeviceList({
  overview,
  canWrite,
  onChanged,
  onSelect,
  onEdit,
}: {
  overview: Overview;
  canWrite: boolean;
  onChanged: () => void;
  onSelect: (hostname: string) => void;
  onEdit?: (hostname: string) => void;
}) {
  async function remove(hostname: string) {
    if (!confirm(`Unregister ${hostname}?`)) return;
    await api.deleteDevice(hostname);
    onChanged();
  }

  const { counts } = overview;
  // Published by the gateway, never assumed here — see `deviceHealth`.
  const staleAfter = overview.stale_after_seconds;
  const states = overview.devices.map((d: Device) => deviceHealth(d, staleAfter));
  const unknown = states.filter((x) => x === "stale").length;
  return (
    <div>
      <p style={{ color: ui.inkSoft }}>
        Mode: <b>{overview.mode}</b> · {counts.total} devices · {counts.active_pods} active ·{" "}
        {counts.reachable} reachable · {counts.unreachable} unreachable
        {/* Surfaced beside the counts because the gateway's own `reachable`/`unreachable`
            split has no room for "we do not currently know" — a device whose reading went
            stale is still counted as one or the other upstream. */}
        {unknown > 0 && <> · {unknown} unknown</>}
      </p>
      <table cellPadding={6} style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            <th align="left">Hostname</th>
            <th align="left">Base URL</th>
            <th>Kind</th>
            <th>Health</th>
            <th>Pod</th>
            {canWrite && <th></th>}
          </tr>
        </thead>
        <tbody>
          {overview.devices.map((d: Device) => (
            <tr key={d.hostname} style={{ borderTop: `1px solid ${ui.rule}` }}>
              <td>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    onSelect(d.hostname);
                  }}
                >
                  {d.hostname}
                </a>
              </td>
              <td>{d.base_url}</td>
              <td align="center">
                <UpstreamKind kind={d.upstream_kind} />
              </td>
              <td align="center">
                <HealthDot state={deviceHealth(d, staleAfter)} title={freshness(d.last_check)} />
              </td>
              <td align="center">{d.pod_active ? "🟢" : "⚪"}</td>
              {canWrite && (
                <td align="center">
                  {onEdit && <button onClick={() => onEdit(d.hostname)}>Edit</button>}{" "}
                  <button onClick={() => remove(d.hostname)}>Remove</button>
                </td>
              )}
            </tr>
          ))}
          {overview.devices.length === 0 && (
            <tr>
              <td colSpan={canWrite ? 6 : 5}>No devices registered.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// What sits behind the device: an OpenAPI service the gateway generates tools from, or a
// remote MCP server it proxies (gateway ADR-0009). The field carries a schema default, so
// an older gateway that omits it reads as "openapi" — which is what it would have been.
function UpstreamKind({ kind }: { kind?: string }) {
  const mcp = kind === "mcp";
  return (
    <span
      title={mcp ? "Proxied remote MCP server" : "Tools generated from an OpenAPI document"}
      style={{
        fontSize: 12,
        padding: "1px 6px",
        borderRadius: 10,
        border: `1px solid ${ui.ruleFirm}`,
        background: mcp ? ui.actSoft : ui.canvas,
        color: ui.inkSoft,
      }}
    >
      {mcp ? "mcp" : "openapi"}
    </span>
  );
}
