// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0020 §4, slice 4 — the tenant-plane claim view. Same load-bearing property as
// CatalogConsole.test.tsx: a failed read must not render as "nothing assigned" (§7). Plus
// the template/instance split — the claim form must ask for the tenant's own fields (host,
// credential) and nothing the curated type already decided (transport, upstream_kind).
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ClaimFromCatalog } from "../components/ClaimFromCatalog";

const { listAssigned, getDeviceType, claim } = vi.hoisted(() => ({
  listAssigned: vi.fn(),
  getDeviceType: vi.fn(),
  claim: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { catalog: { listAssigned, getDeviceType, claim } },
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

const VERSION_API_KEY = {
  id: "v1",
  device_type_id: "t1",
  version: 1,
  transport: "sse",
  upstream_kind: "openapi",
  upstream_transport: "http",
  spec_path: "/openapi.json",
  auth_kind: "api_key",
  fingerprint_policy: "enforce",
  changelog: null,
  created_at: "2026-01-01T00:00:00Z",
};

describe("ClaimFromCatalog", () => {
  beforeEach(() => {
    listAssigned.mockReset();
    getDeviceType.mockReset();
    claim.mockReset();
  });

  it("says plainly when nothing is assigned to this tenant yet", async () => {
    listAssigned.mockResolvedValue({ device_types: [] });
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);
    expect(await screen.findByText(/nothing assigned to this tenant yet/i)).toBeInTheDocument();
  });

  it("lists assigned device types", async () => {
    listAssigned.mockResolvedValue({ device_types: [TYPE] });
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);
    expect(await screen.findByText(/acme-sensor-x1/)).toBeInTheDocument();
  });

  it("does not say 'nothing assigned' when the catalog is actually unreachable", async () => {
    listAssigned.mockRejectedValue(new Error("network down"));
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);
    await waitFor(() =>
      expect(screen.queryByText(/nothing assigned to this tenant yet/i)).not.toBeInTheDocument(),
    );
    expect(await screen.findByText(/could not reach the catalog/i)).toBeInTheDocument();
  });

  it("shows credential fields matching the selected type's auth_kind", async () => {
    listAssigned.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [VERSION_API_KEY] });
    const user = userEvent.setup();
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);

    await user.click(await screen.findByText(/acme-sensor-x1/));

    expect(await screen.findByLabelText(/api key/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/token endpoint/i)).not.toBeInTheDocument();
  });

  it("claims with only the tenant's own fields, never the type's template fields", async () => {
    listAssigned.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [VERSION_API_KEY] });
    claim.mockResolvedValue({ hostname: "sensor-01" });
    const onDone = vi.fn();
    const user = userEvent.setup();
    render(<ClaimFromCatalog onDone={onDone} onCancel={vi.fn()} />);

    await user.click(await screen.findByText(/acme-sensor-x1/));
    await user.type(await screen.findByLabelText(/name for this device/i), "sensor-01");
    await user.type(screen.getByLabelText(/^address$/i), "https://sensor-01.local");
    await user.type(screen.getByLabelText(/^api key$/i), "s3cr3t");
    await user.click(screen.getByRole("button", { name: /^claim$/i }));

    await waitFor(() =>
      expect(claim).toHaveBeenCalledWith("t1", {
        hostname: "sensor-01",
        base_url: "https://sensor-01.local",
        auth: { api_key: "s3cr3t", location: "header", name: "X-API-Key" },
      }),
    );
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("back returns to the list without submitting anything", async () => {
    listAssigned.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [VERSION_API_KEY] });
    const user = userEvent.setup();
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);

    await user.click(await screen.findByText(/acme-sensor-x1/));
    await screen.findByLabelText(/name for this device/i);
    await user.click(screen.getByRole("button", { name: /^back$/i }));

    expect(await screen.findByText(/acme-sensor-x1/)).toBeInTheDocument();
    expect(claim).not.toHaveBeenCalled();
  });
});

// --- product facts the curator supplies (ADR-0020 §2) ---------------------------------------
//
// Where the API key goes and what the appliance tolerates are properties of the PRODUCT. The
// form used to ask for both, defaulting the header name to a hardcoded "X-API-Key" — a
// plausible guess that is wrong for plenty of appliances and fails as a 401 at first contact,
// reading like a bad key rather than a misplaced one.

describe("curated product facts", () => {
  async function openForm(version: Record<string, unknown>) {
    listAssigned.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [{ ...VERSION_API_KEY, ...version }] });
    const user = userEvent.setup();
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);
    await user.click(await screen.findByText(/acme-sensor-x1/));
    await screen.findByLabelText(/api key/i);
    return user;
  }

  it("states where the key goes instead of asking, when the provider has said", async () => {
    await openForm({ api_key_location: "header", api_key_name: "X-Acme-Token" });

    expect(screen.getByTestId("cc-api-curated")).toHaveTextContent("X-Acme-Token");
    // Not merely pre-filled: an editable control would be a field that appears to do
    // something and does not, since the BFF overrides whatever is sent.
    expect(screen.queryByLabelText(/^name$/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^location$/i)).not.toBeInTheDocument();
  });

  it("still asks when the provider has not said", async () => {
    // The direction that catches the feature being wired nowhere: a version predating these
    // fields must keep working exactly as before.
    await openForm({ api_key_location: null, api_key_name: null });

    expect(screen.getByLabelText(/^name$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^location$/i)).toBeInTheDocument();
    expect(screen.queryByTestId("cc-api-curated")).not.toBeInTheDocument();
  });

  it("pre-fills the recommended rate limit, and lets the tenant change it", async () => {
    const user = await openForm({ recommended_rate_limit_rps: 10.5 });
    const rate = screen.getByLabelText(/rate limit/i);
    expect(rate).toHaveValue(10.5);

    // A recommendation, not a ceiling — the control must remain the tenant's.
    await user.clear(rate);
    await user.type(rate, "2");
    expect(rate).toHaveValue(2);
  });

  it("leaves the rate limit empty when there is no recommendation", async () => {
    await openForm({ recommended_rate_limit_rps: null });
    expect(screen.getByLabelText(/rate limit/i)).toHaveValue(null);
  });
});

// ADR-0020 §4c — who supplies the address is a property of the TYPE. Tested in both
// directions: a version predating §4c has no `host_source` at all and must keep asking,
// and asserting only the host-fixed direction would pass just as well if the feature were
// wired nowhere.
describe("who supplies the address (ADR-0020 §4c)", () => {
  async function openForm(version: Record<string, unknown>) {
    listAssigned.mockResolvedValue({ device_types: [TYPE] });
    getDeviceType.mockResolvedValue({ ...TYPE, versions: [{ ...VERSION_API_KEY, ...version }] });
    const user = userEvent.setup();
    render(<ClaimFromCatalog onDone={vi.fn()} onCancel={vi.fn()} />);
    await user.click(await screen.findByText(/acme-sensor-x1/));
    await screen.findByLabelText(/api key/i);
    return user;
  }

  const HOST_FIXED = {
    host_source: "provider_fixed",
    fixed_base_url: "https://svc.provider.example",
  };

  it("does not ask for an address the provider already fixed", async () => {
    await openForm(HOST_FIXED);

    // Absent, not disabled. A greyed-out input still reads as something the tenant chose
    // and could change, and the BFF refuses a supplied address rather than ignoring it.
    expect(screen.queryByLabelText(/address/i)).not.toBeInTheDocument();
    expect(screen.getByTestId("cc-host-fixed")).toHaveTextContent("https://svc.provider.example");
  });

  it("omits base_url from the claim rather than sending an empty one", async () => {
    const user = await openForm(HOST_FIXED);
    await user.type(screen.getByLabelText(/name for this device/i), "svc-01");
    await user.type(screen.getByLabelText(/api key/i), "s3cr3t");

    await user.click(screen.getByRole("button", { name: /^claim$/i }));

    await waitFor(() => expect(claim).toHaveBeenCalledTimes(1));
    expect(claim.mock.calls[0][1]).not.toHaveProperty("base_url");
  });

  it("still asks for the credential — a fixed host is not a provider-operated service", async () => {
    await openForm(HOST_FIXED);
    expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
  });

  it("stops promising the address is the tenant's when it is not", async () => {
    await openForm(HOST_FIXED);
    expect(screen.queryByText(/the address and credentials below are yours/i)).not.toBeInTheDocument();
    expect(screen.getByText(/the credentials below are yours/i)).toBeInTheDocument();
  });

  it("asks for the address when the type does not fix it", async () => {
    await openForm({ host_source: "tenant" });
    expect(screen.getByLabelText(/address/i)).toBeInTheDocument();
    expect(screen.queryByTestId("cc-host-fixed")).not.toBeInTheDocument();
  });

  it("asks for the address on a version curated before §4c existed", async () => {
    // No `host_source` key at all — absent must read as "tenant", not as a missing
    // declaration to fall over on.
    await openForm({});
    expect(screen.getByLabelText(/address/i)).toBeInTheDocument();
  });
});
