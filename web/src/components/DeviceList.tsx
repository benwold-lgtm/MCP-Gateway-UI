// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import type { Device, Overview } from "../types";
import { api } from "../api";

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
  return (
    <div>
      <p>
        Mode: <b>{overview.mode}</b> · {counts.total} devices · {counts.active_pods} active ·{" "}
        {counts.reachable} reachable · {counts.unreachable} unreachable
      </p>
      <table cellPadding={6} style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            <th align="left">Hostname</th>
            <th align="left">Base URL</th>
            <th>Kind</th>
            <th>Reachable</th>
            <th>Pod</th>
            {canWrite && <th></th>}
          </tr>
        </thead>
        <tbody>
          {overview.devices.map((d: Device) => (
            <tr key={d.hostname} style={{ borderTop: "1px solid #ddd" }}>
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
              <td align="center">{d.reachable ? "✅" : "❌"}</td>
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
        border: "1px solid #ccc",
        background: mcp ? "#eef3ff" : "#f4f4f4",
        color: "#444",
      }}
    >
      {mcp ? "mcp" : "openapi"}
    </span>
  );
}
