// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { Diagnostics, Role, Tool, ToolsDiff } from "../types";
import { DeadLetterPanel } from "./DeadLetterPanel";

// Per-device detail: the gateway's diagnostics ("why is my device down?") plus a
// tool explorer (the generated MCP tools and their input schemas). Diagnostics is
// the source of truth for health; the tool list is best-effort (the gateway returns
// 409 when there is no active pod), so a down device still shows its diagnostics.
export function DeviceDetail({
  hostname,
  role,
  onClose,
}: {
  hostname: string;
  role: Role;
  onClose: () => void;
}) {
  const [diag, setDiag] = useState<Diagnostics | null>(null);
  const [tools, setTools] = useState<Tool[] | null>(null);
  const [diff, setDiff] = useState<ToolsDiff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openTool, setOpenTool] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setDiag(null);
    setTools(null);
    setDiff(null);
    setError(null);
    setOpenTool(null);
    Promise.all([
      api.diagnostics(hostname),
      // Tools require an active pod; tolerate failure so diagnostics still render.
      api.tools(hostname).then(
        (t) => t.tools,
        () => [],
      ),
      // Governance — also best-effort; absence just hides the changes panel.
      api.toolsDiff(hostname).then(
        (x) => x,
        () => null,
      ),
    ])
      .then(([d, t, df]) => {
        if (!active) return;
        setDiag(d);
        setTools(t);
        setDiff(df);
      })
      .catch((err) => {
        if (active) setError(err instanceof ApiError ? err.message : "Failed to load device");
      });
    return () => {
      active = false;
    };
  }, [hostname]);

  return (
    <section
      aria-label={`Device detail: ${hostname}`}
      style={{
        border: "1px solid #ddd",
        borderRadius: 8,
        padding: "12px 16px",
        margin: "12px 0",
        background: "#fafafa",
      }}
    >
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <h2 style={{ margin: 0 }}>{hostname}</h2>
        <button onClick={onClose}>Close</button>
      </header>

      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {!diag && !error && <p>Loading…</p>}

      {diag && (
        <>
          <h3>Diagnostics</h3>
          <table cellPadding={4} style={{ borderCollapse: "collapse" }}>
            <tbody>
              <Row label="Reachable" value={diag.reachable ? "✅ yes" : "❌ no"} />
              <Row label="Pod active" value={diag.pod_active ? "🟢 yes" : "⚪ no"} />
              <Row label="Mode" value={diag.mode} />
              <Row label="Base URL" value={diag.base_url} />
              <Row label="Spec URL" value={diag.spec_url ?? "(auto-discovered)"} />
              {diag.worker_id != null && <Row label="Worker" value={diag.worker_id} />}
              <Row
                label="Last check"
                value={diag.last_check_age_seconds != null ? `${diag.last_check_age_seconds}s ago` : "—"}
              />
              <Row label="Spec hash" value={diag.spec_hash ?? "—"} />
              <Row label="Manifest cached" value={diag.has_manifest ? "yes" : "no"} />
              <Row label="Tool count" value={String(diag.tool_count)} />
              <Row label="Tools revision" value={String(diag.tools_revision)} />
              {diag.spawn_error && <Row label="Spawn error" value={diag.spawn_error} danger />}
              <Row label="Circuit breaker" value={breakerText(diag.breaker)} />
            </tbody>
          </table>

          {diff?.last_change && <ToolChanges change={diff.last_change} />}
          {diff && !diff.last_change && (
            <p style={{ color: "#888", marginTop: 12, fontSize: 13 }}>
              No tool-set changes since registration.
            </p>
          )}

          <h3 style={{ marginTop: 16 }}>Tools {tools ? `(${tools.length})` : ""}</h3>
          {tools && tools.length === 0 && (
            <p style={{ color: "#888" }}>
              No tools to show — the device has no active pod or cached manifest (see diagnostics above).
            </p>
          )}
          {tools && tools.length > 0 && (
            <ul style={{ listStyle: "none", padding: 0 }}>
              {tools.map((t) => (
                <li key={t.name} style={{ borderTop: "1px solid #eee", padding: "6px 0" }}>
                  <button
                    onClick={() => setOpenTool(openTool === t.name ? null : t.name)}
                    style={{
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      padding: 0,
                      textAlign: "left",
                    }}
                    aria-expanded={openTool === t.name}
                  >
                    <code style={{ fontWeight: 600 }}>{t.name}</code>{" "}
                    <span style={{ color: "#555", fontSize: 13 }}>
                      {t.method} {t.path}
                    </span>
                  </button>
                  {t.description && <div style={{ color: "#444", fontSize: 13 }}>{t.description}</div>}
                  {openTool === t.name && (
                    <pre
                      style={{
                        background: "#fff",
                        border: "1px solid #eee",
                        padding: 8,
                        overflowX: "auto",
                        fontSize: 12,
                      }}
                    >
                      {JSON.stringify(t.schema, null, 2)}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      <DeadLetterPanel hostname={hostname} role={role} />
    </section>
  );
}

function Row({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <tr>
      <td style={{ color: "#666", paddingRight: 16, verticalAlign: "top" }}>{label}</td>
      <td
        style={{ color: danger ? "crimson" : "inherit", fontFamily: "ui-monospace, monospace", fontSize: 13 }}
      >
        {value}
      </td>
    </tr>
  );
}

function breakerText(b: Diagnostics["breaker"]): string {
  if (!b.available) return b.note ?? "not readable here";
  const state = b.state ?? "unknown";
  return b.fail_max != null ? `${state} (${b.fail_counter ?? 0}/${b.fail_max} failures)` : state;
}

// The device's most recent tool-set change (gateway F-41). Array fields are optional
// in the generated schema, so coalesce before use.
function ToolChanges({ change }: { change: NonNullable<ToolsDiff["last_change"]> }) {
  const reasons = change.breaking_reasons ?? [];
  return (
    <div style={{ marginTop: 16 }}>
      <h3 style={{ marginBottom: 2 }}>
        Recent tool-set change{" "}
        <span style={{ fontSize: 13, color: change.breaking ? "crimson" : "#2a7" }}>
          · {change.breaking ? "breaking" : "compatible"}
        </span>
      </h3>
      <p style={{ color: "#666", fontSize: 13, margin: "2px 0" }}>
        revision {change.tools_revision} · {new Date(change.at * 1000).toLocaleString()}
      </p>
      <ChangeLine label="Added" names={change.added} />
      <ChangeLine label="Removed" names={change.removed} />
      <ChangeLine label="Changed" names={change.changed} />
      {change.breaking && reasons.length > 0 && (
        <ul style={{ color: "crimson", fontSize: 13, margin: "4px 0" }}>
          {reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ChangeLine({ label, names }: { label: string; names?: string[] }) {
  const list = names ?? [];
  if (list.length === 0) return null;
  return (
    <div style={{ fontSize: 13 }}>
      <b>{label}:</b> <code>{list.join(", ")}</code>
    </div>
  );
}
