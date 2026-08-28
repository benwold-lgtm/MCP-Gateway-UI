// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0017 §7, slice 8 — the raise/poll transaction in isolation. `ProviderConsole.test.tsx`
// proves the shell reads `held` correctly; this proves the panel drives raising and polling
// to that state. ADR-0021 (scoped) slice 4 added the tenant selector — a provider console can
// reach more than one tenant now, so raising and polling both name one.
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SupportRequestPanel } from "../components/SupportRequestPanel";

const { raiseSupportRequest, pollSupportRequest, releaseSupportGrant, listTenants } = vi.hoisted(() => ({
  raiseSupportRequest: vi.fn(),
  pollSupportRequest: vi.fn(),
  releaseSupportGrant: vi.fn(),
  listTenants: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { provider: { raiseSupportRequest, pollSupportRequest, releaseSupportGrant, listTenants } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

// The role whose menu each pre-existing case assumes. Made explicit at ADR-0017 §7b, when
// what the panel offers stopped being the same for every provider session.
const ADMIN = ["provider:admin"];
const MONITOR = ["provider:monitor"];

const TENANTS = [
  { tenant_id: "t-1", display_name: "Acme Inc" },
  { tenant_id: "t-2", display_name: "Zeta Corp" },
];

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  raiseSupportRequest.mockReset();
  pollSupportRequest.mockReset();
  releaseSupportGrant.mockReset();
  listTenants.mockReset();
  listTenants.mockResolvedValue({ tenants: TENANTS });
});

afterEach(() => {
  vi.useRealTimers();
});

async function raise(user: ReturnType<typeof userEvent.setup>) {
  await waitFor(() => expect(screen.getByRole("option", { name: "Acme Inc" })).toBeInTheDocument());
  await user.selectOptions(screen.getByLabelText("Tenant"), "t-1");
  await user.click(screen.getByLabelText("devices:read"));
  await user.type(screen.getByPlaceholderText(/justification/i), "INC-9001");
  await user.click(screen.getByRole("button", { name: /raise request/i }));
}

describe("SupportRequestPanel", () => {
  it("cannot raise until a tenant is picked, a scope is picked and a justification is written", async () => {
    render(
      <SupportRequestPanel held={null} providerScopes={ADMIN} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );
    expect(screen.getByRole("button", { name: /raise request/i })).toBeDisabled();
  });

  it("raises against the picked tenant with the picked scopes and justification", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    raiseSupportRequest.mockResolvedValue({
      request_id: "r1",
      requested_scopes: ["devices:read"],
      expires_at: 1,
    });
    pollSupportRequest.mockResolvedValue({ status: "pending" });
    render(
      <SupportRequestPanel held={null} providerScopes={ADMIN} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );

    await raise(user);

    expect(raiseSupportRequest).toHaveBeenCalledWith({
      tenant_id: "t-1",
      requested_scopes: ["devices:read"],
      justification: "INC-9001",
    });
    expect(await screen.findByText(/waiting for acme inc/i)).toBeInTheDocument();
  });

  it("polls the same tenant it raised against, then reports the grant up", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const onGranted = vi.fn();
    raiseSupportRequest.mockResolvedValue({ request_id: "r1", requested_scopes: [], expires_at: 1 });
    pollSupportRequest.mockResolvedValueOnce({ status: "pending" }).mockResolvedValueOnce({
      status: "approved",
      grant_id: "g1",
      credential: "sgr_secret",
    });
    render(
      <SupportRequestPanel held={null} providerScopes={ADMIN} onGranted={onGranted} onReleased={vi.fn()} />,
    );

    await raise(user);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });

    expect(pollSupportRequest).toHaveBeenCalledWith("r1", "t-1");
    await waitFor(() =>
      expect(onGranted).toHaveBeenCalledWith({ held: true, grant_id: "g1", tenant_id: "t-1" }),
    );
  });

  it("stops polling and reports a rejection", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    raiseSupportRequest.mockResolvedValue({ request_id: "r1", requested_scopes: [], expires_at: 1 });
    pollSupportRequest.mockResolvedValue({ status: "rejected" });
    render(
      <SupportRequestPanel held={null} providerScopes={ADMIN} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );

    await raise(user);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });

    expect(await screen.findByText(/the tenant rejected/i)).toBeInTheDocument();
    const pollCallsAtRejection = pollSupportRequest.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000);
    });
    expect(pollSupportRequest.mock.calls.length).toBe(pollCallsAtRejection);
  });

  it("shows the held tenant's display name and never renders the credential itself", async () => {
    render(
      <SupportRequestPanel
        providerScopes={ADMIN}
        held={{ held: true, grant_id: "g1", tenant_id: "t-1" }}
        onGranted={vi.fn()}
        onReleased={vi.fn()}
      />,
    );
    expect(await screen.findByText("Acme Inc", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("g1", { exact: false })).toBeInTheDocument();
    expect(screen.queryByText(/sgr_/)).not.toBeInTheDocument();
  });

  it("falls back to the raw tenant_id if the directory hasn't loaded it", async () => {
    listTenants.mockResolvedValue({ tenants: [] });
    render(
      <SupportRequestPanel
        providerScopes={ADMIN}
        held={{ held: true, grant_id: "g1", tenant_id: "unknown-tenant" }}
        onGranted={vi.fn()}
        onReleased={vi.fn()}
      />,
    );
    expect(await screen.findByText("unknown-tenant", { exact: false })).toBeInTheDocument();
  });

  it("releases the grant and reports it up", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const onReleased = vi.fn();
    releaseSupportGrant.mockResolvedValue({ released: "g1" });
    render(
      <SupportRequestPanel
        providerScopes={ADMIN}
        held={{ held: true, grant_id: "g1", tenant_id: "t-1" }}
        onGranted={vi.fn()}
        onReleased={onReleased}
      />,
    );

    await user.click(screen.getByRole("button", { name: /release grant/i }));

    await waitFor(() => expect(onReleased).toHaveBeenCalled());
  });
  // --- ADR-0017 §7b: what the menu offers follows the role ------------------------------

  it("offers a monitor only the read scopes it is permitted to request", async () => {
    render(
      <SupportRequestPanel held={null} providerScopes={MONITOR} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );

    expect(await screen.findByLabelText("devices:read")).toBeInTheDocument();
    expect(screen.getByLabelText("metrics:read")).toBeInTheDocument();
    // The lab finding, inverted: a box offered here is a raise the BFF would refuse.
    expect(screen.queryByLabelText("devices:write")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("tools:call")).not.toBeInTheDocument();
  });

  it("offers an admin the full routine menu", async () => {
    render(
      <SupportRequestPanel held={null} providerScopes={ADMIN} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );

    for (const scope of ["devices:read", "devices:write", "tools:call", "metrics:read"]) {
      expect(await screen.findByLabelText(scope)).toBeInTheDocument();
    }
  });

  it("lets a monitor actually raise — the panel is not read-only for it", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    raiseSupportRequest.mockResolvedValue({ request_id: "r-1" });
    pollSupportRequest.mockResolvedValue({ status: "pending" });
    render(
      <SupportRequestPanel held={null} providerScopes={MONITOR} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );

    await user.selectOptions(await screen.findByLabelText("Tenant"), "t-1");
    await user.click(screen.getByLabelText("devices:read"));
    await user.type(screen.getByRole("textbox"), "INC-9");
    await user.click(screen.getByRole("button", { name: /raise/i }));

    await waitFor(() =>
      expect(raiseSupportRequest).toHaveBeenCalledWith({
        tenant_id: "t-1",
        requested_scopes: ["devices:read"],
        justification: "INC-9",
      }),
    );
  });

  it("treats a session holding both scopes as an admin", async () => {
    render(
      <SupportRequestPanel
        held={null}
        providerScopes={["provider:monitor", "provider:admin"]}
        onGranted={vi.fn()}
        onReleased={vi.fn()}
      />,
    );

    expect(await screen.findByLabelText("tools:call")).toBeInTheDocument();
  });
});
