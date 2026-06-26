// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Hoisted mocks so the api module factory can reference them.
const { diagnostics, tools } = vi.hoisted(() => ({ diagnostics: vi.fn(), tools: vi.fn() }));

vi.mock("../api", () => ({
  api: { diagnostics, tools },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

import { DeviceDetail } from "../components/DeviceDetail";

const DIAG = {
  hostname: "sensor-1",
  mode: "embedded",
  base_url: "http://sensor-1.local",
  spec_url: null,
  transport: "sse",
  reachable: true,
  pod_active: true,
  worker_id: null,
  last_check: 1717500000.0,
  last_check_age_seconds: 4.2,
  spec_hash: "abc123",
  has_manifest: true,
  tool_count: 1,
  tools_revision: 3,
  spawn_error: null,
  breaker: { available: true, state: "closed", fail_counter: 0, fail_max: 5, reset_timeout: 60, note: null },
};

const TOOLS = {
  hostname: "sensor-1",
  count: 1,
  tools: [
    {
      name: "get_readings",
      description: "Read samples",
      schema: { type: "object" },
      method: "GET",
      path: "/r",
    },
  ],
};

describe("DeviceDetail", () => {
  beforeEach(() => {
    diagnostics.mockReset();
    tools.mockReset();
  });

  it("renders diagnostics and the tool explorer", async () => {
    diagnostics.mockResolvedValue(DIAG);
    tools.mockResolvedValue(TOOLS);
    render(<DeviceDetail hostname="sensor-1" onClose={vi.fn()} />);

    expect(await screen.findByRole("heading", { name: "sensor-1" })).toBeInTheDocument();
    // Diagnostics + breaker.
    expect(screen.getByText(/closed \(0\/5 failures\)/)).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument(); // tools_revision
    // Tool is listed; its schema is revealed on click.
    const toolButton = screen.getByRole("button", { name: /get_readings/ });
    expect(screen.queryByText(/"type": "object"/)).not.toBeInTheDocument();
    await userEvent.click(toolButton);
    await waitFor(() => expect(screen.getByText(/"type": "object"/)).toBeInTheDocument());
  });

  it("still shows diagnostics when the tools call fails (no active pod)", async () => {
    diagnostics.mockResolvedValue({ ...DIAG, pod_active: false, reachable: false });
    tools.mockRejectedValue(new Error("409"));
    render(<DeviceDetail hostname="sensor-1" onClose={vi.fn()} />);

    expect(await screen.findByRole("heading", { name: "sensor-1" })).toBeInTheDocument();
    expect(screen.getByText(/No tools to show/)).toBeInTheDocument();
  });
});
