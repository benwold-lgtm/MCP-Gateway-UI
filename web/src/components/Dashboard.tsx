// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api } from "../api";
import type { LokiResponse, MonitoringMeta, Overview, PromQueryResponse } from "../types";
import { health, ui } from "../tokens";

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

/** The same view without a Prometheus, from counts the gateway already publishes.
 *
 * A deployment with no `PROMETHEUS_URL` used to get one sentence naming an env var and
 * nothing else — on Lite, where standing up a TSDB is the opposite of the point, that made
 * Monitoring a tab you could open once. Two of the four tiles above are plain registry facts
 * and `GET /admin/overview` has been returning them all along; the console fetches that
 * endpoint on the devices screen already.
 *
 * These are **not** a substitute for the Prometheus tiles and the copy does not pretend
 * otherwise. They are instantaneous, they have no history, and two of the four metrics above
 * (SSE connections, worker queue depth) are not registry facts and are genuinely absent here.
 * What they are is true, which the previous state was not offering at all.
 */
function overviewTiles(overview: Overview): { label: string; value: string }[] {
  const c = overview.counts;
  return [
    { label: "Registered devices", value: String(c.total) },
    { label: "Active pods", value: String(c.active_pods) },
    { label: "Reachable", value: String(c.reachable) },
    { label: "Unreachable", value: String(c.unreachable) },
  ];
}

function promValue(r: PromQueryResponse): string {
  return r.data?.result?.[0]?.value?.[1] ?? "—";
}

export function Dashboard() {
  const [meta, setMeta] = useState<MonitoringMeta | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [logs, setLogs] = useState<LokiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.monitoringMeta().then(
      async (m) => {
        if (!active) return;
        setMeta(m);
        if (!m.prometheus_enabled) {
          // Only fetched when there is no Prometheus — where there is one, its tiles are
          // strictly better (summed across workers, and the same numbers the alerting sees).
          api.overview().then(
            (o) => active && setOverview(o),
            () => active && setOverview(null),
          );
        }
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
      {error && <p style={{ color: health.fail }}>{error}</p>}
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
          ) : overview ? (
            <>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                {overviewTiles(overview).map((t) => (
                  <Tile key={t.label} label={t.label} value={t.value} />
                ))}
              </div>
              <p style={{ color: ui.muted, maxWidth: 640, fontSize: "0.9em", marginTop: 10 }}>
                Live counts from the gateway — no history, and no SSE-connection or worker-queue figures,
                which are not registry facts. Set <code>PROMETHEUS_URL</code> on the BFF for those and for
                anything over time.
              </p>
            </>
          ) : (
            <p style={{ color: ui.muted }}>
              Prometheus is not configured (set <code>PROMETHEUS_URL</code> on the BFF). Use central
              monitoring below.
            </p>
          )}

          <h3 style={{ marginTop: 20 }}>Central monitoring</h3>
          <p style={{ color: ui.inkSoft, maxWidth: 640 }}>
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
            <p style={{ color: ui.muted }}>
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
        border: `1px solid ${ui.rule}`,
        borderRadius: 8,
        padding: "10px 14px",
        minWidth: 150,
        background: "#fff",
      }}
    >
      <div style={{ fontSize: 24, fontWeight: 600 }}>{value}</div>
      <div style={{ fontSize: 13, color: ui.inkSoft }}>{label}</div>
    </div>
  );
}

function LogView({ logs }: { logs: LokiResponse | null }) {
  if (!logs) return <p>Loading logs…</p>;
  const lines = (logs.data?.result ?? [])
    .flatMap((s) => s.values.map(([ts, line]) => ({ ts: Number(ts), line })))
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 100);
  if (lines.length === 0) return <p style={{ color: ui.muted }}>No recent log lines.</p>;
  return (
    <pre
      style={{
        background: "#fff",
        border: `1px solid ${ui.rule}`,
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
          <span style={{ color: ui.muted }}>{new Date(l.ts / 1_000_000).toLocaleTimeString()}</span> {l.line}
        </div>
      ))}
    </pre>
  );
}
