// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { DeviceFull, Diagnostics, Tool, ToolsDiff } from "../types";
import { DeadLetterPanel } from "./DeadLetterPanel";
import { FingerprintPanel } from "./FingerprintPanel";
import { NeedsReconnectBanner } from "./CredentialState";
import { ToolInvoke } from "./ToolInvoke";
import { health, ui } from "../tokens";

// Per-device detail: the gateway's diagnostics ("why is my device down?"), the endpoint
// fingerprint (what the device *is*), and a tool explorer. Diagnostics is the source of
// truth for health; the tool list is best-effort (the gateway returns 409 when there is
// no active pod), so a down device still shows its diagnostics.
//
// The fingerprint fields live on the device record rather than on diagnostics, so this
// view reads both.
export function DeviceDetail({
  hostname,
  canWrite,
  canInvoke = false,
  invokeReason,
  onClose,
}: {
  hostname: string;
  canWrite: boolean;
  /** Whether this session may *call* a tool, which is a different authority from writing a
   *  device record: a tenant admin holds `tools:call` as an ordinary scope. A provider
   *  operator currently has no path to this at all (ADR-0017 slice 6). Defaults to false so
   *  a caller that has not thought about it does not hand out a Run button. */
  canInvoke?: boolean;
  /** Shown in the tool panel when `canInvoke` is false — what would change that. */
  invokeReason?: string;
  onClose: () => void;
}) {
  const [diag, setDiag] = useState<Diagnostics | null>(null);
  const [device, setDevice] = useState<DeviceFull | null>(null);
  const [tools, setTools] = useState<Tool[] | null>(null);
  const [diff, setDiff] = useState<ToolsDiff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openTool, setOpenTool] = useState<string | null>(null);
  // Bumped after an approval so the whole view re-reads: the pin moves, and under an
  // enforce policy the quarantine lifts, which can make the tool list available again.
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let active = true;
    setDiag(null);
    setDevice(null);
    setTools(null);
    setDiff(null);
    setError(null);
    setOpenTool(null);
    Promise.all([
      api.diagnostics(hostname),
      // The device record carries the fingerprint. Tolerated like the others so a
      // failure here cannot blank the health view; the panel is hidden and said to be.
      api.getDevice(hostname).then(
        (d) => d,
        () => null,
      ),
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
      .then(([d, dev, t, df]) => {
        if (!active) return;
        setDiag(d);
        setDevice(dev);
        setTools(t);
        setDiff(df);
      })
      .catch((err) => {
        if (active) setError(err instanceof ApiError ? err.message : "Failed to load device");
      });
    return () => {
      active = false;
    };
  }, [hostname, reload]);

  return (
    <section
      aria-label={`Device detail: ${hostname}`}
      style={{
        border: `1px solid ${ui.rule}`,
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

      {/* Above Diagnostics, not inside it. Every reading in that table can be green while this
          is true — it is an authorization condition, not a health one. */}
      {device && <NeedsReconnectBanner device={device} />}

      {error && <p style={{ color: health.fail }}>{error}</p>}
      {!diag && !error && <p>Loading…</p>}

      {diag && (
        <>
          <h3>Diagnostics</h3>
          <table cellPadding={4} style={{ borderCollapse: "collapse" }}>
            <tbody>
              <Row label="Reachable" value={diag.reachable ? "✅ yes" : "❌ no"} />
              <Row label="Pod active" value={diag.pod_active ? "🟢 yes" : "⚪ no"} />
              <Row label="Mode" value={diag.mode} />
              <Row
                label="Upstream"
                value={diag.upstream_kind === "mcp" ? "mcp (proxied server)" : "openapi"}
              />
              <Row label="Base URL" value={diag.base_url} />
              {/* An MCP upstream has no OpenAPI document, so the gateway rejects spec_url for
                  it (ADR-0009) — say that rather than "(auto-discovered)", which never happens. */}
              <Row
                label="Spec URL"
                value={
                  diag.upstream_kind === "mcp"
                    ? "— (not used by an MCP upstream)"
                    : (diag.spec_url ?? "(auto-discovered)")
                }
              />
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

          {device ? (
            <FingerprintPanel
              device={device}
              tls={diag.tls}
              canWrite={canWrite}
              onApproved={() => setReload((n) => n + 1)}
            />
          ) : (
            // Don't leave a security panel silently absent — an operator would read a
            // missing fingerprint section as "this device has none".
            <p style={{ color: ui.muted, marginTop: 16, fontSize: 13 }}>
              Endpoint fingerprint unavailable — the device record could not be read.
            </p>
          )}

          {diff?.last_change && <ToolChanges change={diff.last_change} />}
          {diff && !diff.last_change && (
            <p style={{ color: ui.muted, marginTop: 12, fontSize: 13 }}>
              No tool-set changes since registration.
            </p>
          )}

          <h3 style={{ marginTop: 16 }}>Tools {tools ? `(${tools.length})` : ""}</h3>
          {tools && tools.length === 0 && (
            <p style={{ color: ui.muted }}>
              No tools to show — the device has no active pod or cached manifest (see diagnostics above).
            </p>
          )}
          {tools && tools.length > 0 && (
            <ul style={{ listStyle: "none", padding: 0 }}>
              {tools.map((t) => (
                <li key={t.name} style={{ borderTop: `1px solid ${ui.rule}`, padding: "6px 0" }}>
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
                    <span style={{ color: ui.inkSoft, fontSize: 13 }}>
                      {t.method} {t.path}
                    </span>
                  </button>
                  {t.description && <div style={{ color: ui.inkSoft, fontSize: 13 }}>{t.description}</div>}
                  {openTool === t.name && (
                    <>
                      <ToolInvoke hostname={hostname} tool={t} canInvoke={canInvoke} reason={invokeReason} />
                      <details style={{ marginTop: 8 }}>
                        <summary style={{ cursor: "pointer", fontSize: 12, color: ui.inkSoft }}>
                          Schema
                        </summary>
                        <pre
                          style={{
                            background: "#fff",
                            border: `1px solid ${ui.rule}`,
                            padding: 8,
                            overflowX: "auto",
                            fontSize: 12,
                            margin: "4px 0 0",
                          }}
                        >
                          {JSON.stringify(t.schema, null, 2)}
                        </pre>
                      </details>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      <DeadLetterPanel hostname={hostname} canWrite={canWrite} />
    </section>
  );
}

function Row({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <tr>
      <td style={{ color: ui.inkSoft, paddingRight: 16, verticalAlign: "top" }}>{label}</td>
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
      <p style={{ color: ui.inkSoft, fontSize: 13, margin: "2px 0" }}>
        revision {change.tools_revision} · {new Date(change.at * 1000).toLocaleString()}
      </p>
      <ChangeLine label="Added" names={change.added} />
      <ChangeLine label="Removed" names={change.removed} />
      <ChangeLine label="Changed" names={change.changed} />
      {change.breaking && reasons.length > 0 && (
        <ul style={{ color: health.fail, fontSize: 13, margin: "4px 0" }}>
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
