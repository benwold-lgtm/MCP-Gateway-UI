// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import type { Device, Overview, Role } from "../types";
import { api } from "../api";

export function DeviceList({
  overview,
  role,
  onChanged,
  onSelect,
  onEdit,
}: {
  overview: Overview;
  role: Role;
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
            <th>Reachable</th>
            <th>Pod</th>
            {role === "admin" && <th></th>}
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
              <td align="center">{d.reachable ? "✅" : "❌"}</td>
              <td align="center">{d.pod_active ? "🟢" : "⚪"}</td>
              {role === "admin" && (
                <td align="center">
                  {onEdit && <button onClick={() => onEdit(d.hostname)}>Edit</button>}{" "}
                  <button onClick={() => remove(d.hostname)}>Remove</button>
                </td>
              )}
            </tr>
          ))}
          {overview.devices.length === 0 && (
            <tr>
              <td colSpan={5}>No devices registered.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
