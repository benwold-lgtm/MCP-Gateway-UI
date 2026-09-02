// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { monitoringMeta, prometheusQuery, logs, overview } = vi.hoisted(() => ({
  monitoringMeta: vi.fn(),
  prometheusQuery: vi.fn(),
  logs: vi.fn(),
  overview: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { monitoringMeta, prometheusQuery, logs, overview },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

import { Dashboard } from "../components/Dashboard";

const prom = (v: string) => ({
  status: "success",
  data: { resultType: "vector", result: [{ metric: {}, value: [0, v] }] },
});

describe("Dashboard", () => {
  beforeEach(() => {
    monitoringMeta.mockReset();
    prometheusQuery.mockReset();
    logs.mockReset();
    overview.mockReset();
    overview.mockResolvedValue({
      mode: "embedded",
      counts: { total: 3, active_pods: 2, reachable: 2, unreachable: 1 },
      devices: [],
    });
  });

  it("renders critical-metric tiles and recent logs when configured", async () => {
    monitoringMeta.mockResolvedValue({
      prometheus_enabled: true,
      loki_enabled: true,
      grafana_url: "http://grafana",
    });
    prometheusQuery.mockImplementation((q: string) =>
      Promise.resolve(prom(q.includes("pods") ? "11" : "12")),
    );
    logs.mockResolvedValue({
      status: "success",
      data: {
        resultType: "streams",
        result: [{ stream: {}, values: [["1717500000000000000", "hello log"]] }],
      },
    });
    render(<Dashboard />);

    // A tile value from a Prometheus query.
    expect(await screen.findByText("11")).toBeInTheDocument(); // active pods
    expect(screen.getByText("Active pods")).toBeInTheDocument();
    // Central-monitoring pointer + Grafana link.
    expect(screen.getByText(/Run full dashboards in your central monitoring/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open Grafana/ })).toHaveAttribute("href", "http://grafana");
    // A log line.
    expect(await screen.findByText(/hello log/)).toBeInTheDocument();
  });

  it("does not query Prometheus when it is not configured", async () => {
    monitoringMeta.mockResolvedValue({ prometheus_enabled: false, loki_enabled: false, grafana_url: null });
    render(<Dashboard />);

    expect(await screen.findByText(/Loki is not configured/)).toBeInTheDocument();
    expect(prometheusQuery).not.toHaveBeenCalled();
  });

  // --- without a Prometheus ---------------------------------------------------------------
  //
  // A deployment with no `PROMETHEUS_URL` used to get one sentence naming an env var. On Lite,
  // where standing up a TSDB is the opposite of the point, that made Monitoring a tab you
  // could open once. Two of the four tiles are plain registry facts that `/admin/overview` has
  // been returning all along.

  it("fills the tiles from the gateway's own counts when Prometheus is absent", async () => {
    monitoringMeta.mockResolvedValue({ prometheus_enabled: false, loki_enabled: false, grafana_url: null });
    render(<Dashboard />);

    expect(await screen.findByText("Registered devices")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Unreachable")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.queryByText(/Prometheus is not configured/)).not.toBeInTheDocument();
  });

  it("says plainly what these numbers are not", async () => {
    // They are instantaneous, and two of the four Prometheus metrics are genuinely absent.
    // A fallback that read as equivalent would be worse than the empty state it replaces:
    // an operator would stop looking for the ones that are missing.
    monitoringMeta.mockResolvedValue({ prometheus_enabled: false, loki_enabled: false, grafana_url: null });
    render(<Dashboard />);

    expect(await screen.findByText(/no history/)).toBeInTheDocument();
    expect(screen.getByText(/PROMETHEUS_URL/)).toBeInTheDocument();
    // The two it cannot show are not quietly dropped from the vocabulary.
    expect(screen.queryByText("Active SSE connections")).not.toBeInTheDocument();
    expect(screen.queryByText("Worker pending calls")).not.toBeInTheDocument();
  });

  it("falls back to naming the setting when the counts cannot be read either", async () => {
    monitoringMeta.mockResolvedValue({ prometheus_enabled: false, loki_enabled: false, grafana_url: null });
    overview.mockRejectedValue(new Error("gateway down"));
    render(<Dashboard />);

    expect(await screen.findByText(/Prometheus is not configured/)).toBeInTheDocument();
  });

  it("does not fetch the overview when Prometheus IS configured", async () => {
    // Its tiles are strictly better there — summed across workers, and the same numbers the
    // alerting sees. Fetching both would invite two answers to one question.
    monitoringMeta.mockResolvedValue({ prometheus_enabled: true, loki_enabled: false, grafana_url: null });
    prometheusQuery.mockResolvedValue(prom("7"));
    render(<Dashboard />);

    // All four tiles answer 7 from the same stub, so assert on the tile label instead.
    await screen.findByText("Worker pending calls");
    expect(overview).not.toHaveBeenCalled();
  });
});
