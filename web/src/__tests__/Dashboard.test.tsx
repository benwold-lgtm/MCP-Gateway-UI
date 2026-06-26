// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { monitoringMeta, prometheusQuery, logs } = vi.hoisted(() => ({
  monitoringMeta: vi.fn(),
  prometheusQuery: vi.fn(),
  logs: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { monitoringMeta, prometheusQuery, logs },
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

  it("points at central monitoring when Prometheus/Loki are not configured", async () => {
    monitoringMeta.mockResolvedValue({ prometheus_enabled: false, loki_enabled: false, grafana_url: null });
    render(<Dashboard />);

    expect(await screen.findByText(/Prometheus is not configured/)).toBeInTheDocument();
    expect(screen.getByText(/Loki is not configured/)).toBeInTheDocument();
    // No tile queries are issued when Prometheus is off.
    expect(prometheusQuery).not.toHaveBeenCalled();
  });
});
