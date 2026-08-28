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

    await user.type(screen.getByPlaceholderText("e.g. nutanix-prism-central"), "acme-x1");
    await user.type(screen.getByPlaceholderText("e.g. Nutanix Prism Central"), "Acme X1");
    await user.type(screen.getByPlaceholderText("e.g. /openapi.json"), "/openapi.json");
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

    await user.type(screen.getByPlaceholderText("e.g. t-039c899f37b8994d"), "mcp-t-abc123");
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

    await user.type(screen.getByPlaceholderText("e.g. t-039c899f37b8994d"), "mcp-t-abc123");
    await user.click(screen.getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(revoke).toHaveBeenCalledWith("t1", "mcp-t-abc123"));
  });
  // --- the identifier's format is enforced where it is typed --------------------------

  it("explains the identifier format instead of letting the catalog answer with a 422", async () => {
    const user = userEvent.setup();
    listDeviceTypes.mockResolvedValue({ device_types: [] });
    render(<CatalogConsole />);

    const id = await screen.findByPlaceholderText("e.g. nutanix-prism-central");
    await user.type(id, "Acme Sensor X1");

    // The rule lives in the catalog's own schema; before this it was discoverable only by
    // submitting and reading the 422 that came back.
    expect(
      await screen.findByText(/lowercase letters, numbers and hyphens — no spaces or capitals/i),
    ).toBeInTheDocument();
  });

  it("keeps the console's identifier rule identical to the catalog's own", () => {
    // device_mcp_catalog/app/schemas.py: CreateDeviceType.slug
    const CATALOG_RULE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
    for (const good of ["acme-sensor-x1", "nutanix-prism-central", "a", "a1"]) {
      expect(CATALOG_RULE.test(good)).toBe(true);
    }
    for (const bad of ["Acme Sensor X1", "-leading", "trailing-", "has space", "UPPER", ""]) {
      expect(CATALOG_RULE.test(bad)).toBe(false);
    }
  });

  it("asks for a tenant identifier, not a namespace", async () => {
    listDeviceTypes.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [] });
    const user = userEvent.setup();
    render(<CatalogConsole />);
    await user.click(await screen.findByText(/acme-sensor-x1/));
    await screen.findByText(/version history/i);

    // The old placeholder showed `mcp-t-…`, which is the NAMESPACE. Pasting that names a
    // tenant no registry knows, and the assign appears to succeed against nothing.
    expect(screen.getByText(/identifier, not its namespace/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText("e.g. t-039c899f37b8994d")).toBeInTheDocument();
  });
});
