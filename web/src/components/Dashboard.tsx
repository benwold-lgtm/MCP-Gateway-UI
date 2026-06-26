// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api } from "../api";
import type { LokiResponse, MonitoringMeta, PromQueryResponse } from "../types";

// A deliberately small monitoring view: a handful of critical at-a-glance metrics
// and recent logs. Full dashboards belong in central monitoring — this view points
// operators there (gateway /metrics on :9100, optional Grafana link) rather than
// trying to be a monitoring app.
const TILES: { label: string; query: string }[] = [
  { label: "Registered devices", query: "sum(mcp_registered_devices)" },
  { label: "Active pods", query: "sum(mcp_active_pods)" },
  { label: "Active SSE connections", query: "sum(mcp_active_sse_connections)" },
  { label: "Worker pending calls", query: "sum(mcp_worker_pending_calls)" },
];

function promValue(r: PromQueryResponse): string {
  return r.data?.result?.[0]?.value?.[1] ?? "—";
}

export function Dashboard() {
  const [meta, setMeta] = useState<MonitoringMeta | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [logs, setLogs] = useState<LokiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.monitoringMeta().then(
      async (m) => {
        if (!active) return;
        setMeta(m);
        if (m.prometheus_enabled) {
          const pairs = await Promise.all(
            TILES.map((t) =>
              api.prometheusQuery(t.query).then(
                (r) => [t.label, promValue(r)] as const,
                () => [t.label, "—"] as const,
              ),
            ),
          );
          if (active) setValues(Object.fromEntries(pairs));
        }
        if (m.loki_enabled) {
          api.logs().then(
            (l) => active && setLogs(l),
            () => {},
          );
        }
      },
      (e) => {
        if (active) setError(e instanceof Error ? e.message : "Failed to load monitoring");
      },
    );
    return () => {
      active = false;
    };
  }, []);

  return (
    <section>
      <h2>Monitoring</h2>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {!meta && !error && <p>Loading…</p>}

      {meta && (
        <>
          <h3>Critical metrics</h3>
          {meta.prometheus_enabled ? (
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {TILES.map((t) => (
                <Tile key={t.label} label={t.label} value={values[t.label] ?? "…"} />
              ))}
            </div>
          ) : (
            <p style={{ color: "#888" }}>
              Prometheus is not configured (set <code>PROMETHEUS_URL</code> on the BFF). Use central
              monitoring below.
            </p>
          )}

          <h3 style={{ marginTop: 20 }}>Central monitoring</h3>
          <p style={{ color: "#444", maxWidth: 640 }}>
            This view shows only critical metrics at a glance. Run full dashboards in your central monitoring:
            the gateway and workers expose Prometheus metrics on <code>:9100/metrics</code> — point your
            scraper there (see <code>docs/observability.md</code> in the gateway repo).
          </p>
          {meta.grafana_url && (
            <p>
              <a href={meta.grafana_url} target="_blank" rel="noreferrer">
                Open Grafana ↗
              </a>
            </p>
          )}

          <h3 style={{ marginTop: 20 }}>Recent logs</h3>
          {meta.loki_enabled ? (
            <LogView logs={logs} />
          ) : (
            <p style={{ color: "#888" }}>
              Loki is not configured (set <code>LOKI_URL</code> on the BFF). Logs live in your central logging
              stack.
            </p>
          )}
        </>
      )}
    </section>
  );
}

function Tile({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        border: "1px solid #ddd",
        borderRadius: 8,
        padding: "10px 14px",
        minWidth: 150,
        background: "#fff",
      }}
    >
      <div style={{ fontSize: 24, fontWeight: 600 }}>{value}</div>
      <div style={{ fontSize: 13, color: "#666" }}>{label}</div>
    </div>
  );
}

function LogView({ logs }: { logs: LokiResponse | null }) {
  if (!logs) return <p>Loading logs…</p>;
  const lines = (logs.data?.result ?? [])
    .flatMap((s) => s.values.map(([ts, line]) => ({ ts: Number(ts), line })))
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 100);
  if (lines.length === 0) return <p style={{ color: "#888" }}>No recent log lines.</p>;
  return (
    <pre
      style={{
        background: "#fff",
        border: "1px solid #eee",
        padding: 8,
        maxHeight: 360,
        overflow: "auto",
        fontSize: 12,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}
    >
      {lines.map((l, i) => (
        <div key={i}>
          <span style={{ color: "#999" }}>{new Date(l.ts / 1_000_000).toLocaleTimeString()}</span> {l.line}
        </div>
      ))}
    </pre>
  );
}
