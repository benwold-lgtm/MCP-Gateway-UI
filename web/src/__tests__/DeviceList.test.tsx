// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, within } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

vi.mock("../api", () => ({
  api: { deleteDevice: vi.fn() },
  ApiError: class ApiError extends Error {},
}));

import { DeviceList } from "../components/DeviceList";
import type { Overview } from "../types";

// Deliberately NOT pre-seeded with upstream_kind on every row: a gateway older than the
// field omits it, and the schema default says that reads as "openapi". Seeding both rows
// would only ever exercise the branch the implementation already agrees with.
const OVERVIEW = {
  mode: "distributed",
  counts: { total: 3, active_pods: 3, reachable: 3, unreachable: 0 },
  devices: [
    {
      hostname: "refmcp",
      base_url: "http://refmcp:8080/mcp",
      transport: "sse",
      reachable: true,
      pod_active: true,
      upstream_kind: "mcp",
    },
    {
      hostname: "prism",
      base_url: "https://prism:9440",
      transport: "sse",
      reachable: true,
      pod_active: true,
      upstream_kind: "openapi",
    },
    {
      hostname: "legacy",
      base_url: "http://legacy.local",
      transport: "sse",
      reachable: true,
      pod_active: true,
    },
  ],
} as unknown as Overview;

function rowFor(hostname: string) {
  return screen.getByRole("cell", { name: hostname }).closest("tr")!;
}

describe("DeviceList", () => {
  it("distinguishes a proxied MCP upstream from an OpenAPI one", () => {
    render(
      <DeviceList
        overview={OVERVIEW}
        canWrite={false}
        onChanged={vi.fn()}
        onSelect={vi.fn()}
        onEdit={vi.fn()}
      />,
    );

    expect(within(rowFor("refmcp")).getByText("mcp")).toBeInTheDocument();
    expect(within(rowFor("prism")).getByText("openapi")).toBeInTheDocument();
    // The field is absent entirely — the schema default must carry it, not a crash or a blank.
    expect(within(rowFor("legacy")).getByText("openapi")).toBeInTheDocument();
  });

  it("spans the full width of the table when there are no devices", () => {
    const empty = {
      ...OVERVIEW,
      devices: [],
      counts: { total: 0, active_pods: 0, reachable: 0, unreachable: 0 },
    };
    const { rerender } = render(
      <DeviceList
        overview={empty as unknown as Overview}
        canWrite={false}
        onChanged={vi.fn()}
        onSelect={vi.fn()}
        onEdit={vi.fn()}
      />,
    );
    expect(screen.getByText("No devices registered.")).toHaveAttribute("colspan", "5");

    // The actions column only exists for a writer, so the span has to follow it.
    rerender(
      <DeviceList
        overview={empty as unknown as Overview}
        canWrite={true}
        onChanged={vi.fn()}
        onSelect={vi.fn()}
        onEdit={vi.fn()}
      />,
    );
    expect(screen.getByText("No devices registered.")).toHaveAttribute("colspan", "6");
  });
});
