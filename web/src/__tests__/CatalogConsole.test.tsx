// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0020 §1/§2, slice 3 — the minimal provider console surface. The one property worth a
// dedicated test is a shape that recurs across this console's other panels too: a failure
// must read differently from an empty result. "The catalog is unreachable" and
// "nothing has been curated yet" are different problems with different fixes (§7), and a
// console that collapses them into the same blank list teaches an operator the wrong one.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CatalogConsole } from "../components/CatalogConsole";

const { listDeviceTypes, getDeviceType, createDeviceType, assign, revoke } = vi.hoisted(() => ({
  listDeviceTypes: vi.fn(),
  getDeviceType: vi.fn(),
  createDeviceType: vi.fn(),
  assign: vi.fn(),
  revoke: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { provider: { catalog: { listDeviceTypes, getDeviceType, createDeviceType, assign, revoke } } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const TYPE = {
  id: "t1",
  slug: "acme-sensor-x1",
  name: "Acme Sensor X1",
  description: null,
  created_at: "2026-01-01T00:00:00Z",
  latest_version: 1,
};

describe("CatalogConsole", () => {
  beforeEach(() => {
    listDeviceTypes.mockReset();
    getDeviceType.mockReset();
    createDeviceType.mockReset();
    assign.mockReset();
    revoke.mockReset();
  });

  it("says plainly when nothing has been curated yet", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [] });
    render(<CatalogConsole />);
    expect(await screen.findByText(/nothing curated yet/i)).toBeInTheDocument();
  });

  it("lists curated device types with their latest version", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [TYPE] });
    render(<CatalogConsole />);
    expect(await screen.findByText(/acme-sensor-x1/)).toBeInTheDocument();
    expect(screen.getByText(/v1/)).toBeInTheDocument();
  });

  it("does not say 'nothing curated' when the catalog is actually unreachable", async () => {
    // The load-bearing property (ADR-0020 §7): a failed read must not render the same
    // empty-list message a truly empty catalog would.
    listDeviceTypes.mockRejectedValue(new Error("network down"));
    render(<CatalogConsole />);
    await waitFor(() => expect(screen.queryByText(/nothing curated yet/i)).not.toBeInTheDocument());
    expect(await screen.findByText(/could not reach the catalog service/i)).toBeInTheDocument();
  });

  it("creates a device type with the typed fields and refreshes the list", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [] });
    createDeviceType.mockResolvedValue({ ...TYPE, versions: [] });
    const user = userEvent.setup();
    render(<CatalogConsole />);
    await screen.findByText(/nothing curated yet/i);

    await user.type(screen.getByPlaceholderText("acme-sensor-x1"), "acme-x1");
    await user.type(screen.getByPlaceholderText("Acme Sensor X1"), "Acme X1");
    await user.type(screen.getByPlaceholderText("/openapi.json"), "/openapi.json");
    await user.click(screen.getByRole("button", { name: /^create$/i }));

    await waitFor(() =>
      expect(createDeviceType).toHaveBeenCalledWith({
        slug: "acme-x1",
        name: "Acme X1",
        description: undefined,
        upstream_kind: "openapi",
        spec_path: "/openapi.json",
      }),
    );
    expect(listDeviceTypes).toHaveBeenCalledTimes(2); // once on mount, once after creation
  });

  it("hides the spec_path field for an mcp device type", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [] });
    const user = userEvent.setup();
    render(<CatalogConsole />);
    await screen.findByText(/nothing curated yet/i);

    await user.selectOptions(screen.getByRole("combobox"), "mcp");

    expect(screen.queryByPlaceholderText("/openapi.json")).not.toBeInTheDocument();
  });

  it("opening a type shows its version history", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({
      ...TYPE,
      versions: [
        {
          id: "v1",
          device_type_id: "t1",
          version: 1,
          transport: "sse",
          upstream_kind: "openapi",
          upstream_transport: "http",
          spec_path: "/openapi.json",
          auth_kind: "none",
          changelog: null,
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
    });
    const user = userEvent.setup();
    render(<CatalogConsole />);

    await user.click(await screen.findByText(/acme-sensor-x1/));

    expect(await screen.findByText(/version history/i)).toBeInTheDocument();
    expect(screen.getByText(/v1 — openapi \(\/openapi.json\)/)).toBeInTheDocument();
  });

  it("assigns to the typed tenant id", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [] });
    assign.mockResolvedValue({ id: "a1" });
    const user = userEvent.setup();
    render(<CatalogConsole />);
    await user.click(await screen.findByText(/acme-sensor-x1/));
    await screen.findByText(/version history/i);

    await user.type(screen.getByPlaceholderText(/mcp-t-/), "mcp-t-abc123");
    await user.click(screen.getByRole("button", { name: /^assign$/i }));

    await waitFor(() => expect(assign).toHaveBeenCalledWith("t1", "mcp-t-abc123"));
  });

  it("revokes for the typed tenant id", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [] });
    revoke.mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(<CatalogConsole />);
    await user.click(await screen.findByText(/acme-sensor-x1/));
    await screen.findByText(/version history/i);

    await user.type(screen.getByPlaceholderText(/mcp-t-/), "mcp-t-abc123");
    await user.click(screen.getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(revoke).toHaveBeenCalledWith("t1", "mcp-t-abc123"));
  });
});
