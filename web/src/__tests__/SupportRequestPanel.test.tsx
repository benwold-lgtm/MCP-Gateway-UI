// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0017 §7, slice 8 — the raise/poll transaction in isolation. `ProviderConsole.test.tsx`
// proves the shell reads `held` correctly; this proves the panel drives raising and polling
// to that state.
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SupportRequestPanel } from "../components/SupportRequestPanel";

const { raiseSupportRequest, pollSupportRequest, releaseSupportGrant } = vi.hoisted(() => ({
  raiseSupportRequest: vi.fn(),
  pollSupportRequest: vi.fn(),
  releaseSupportGrant: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { provider: { raiseSupportRequest, pollSupportRequest, releaseSupportGrant } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  raiseSupportRequest.mockReset();
  pollSupportRequest.mockReset();
  releaseSupportGrant.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

async function raise(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByLabelText("devices:read"));
  await user.type(screen.getByPlaceholderText(/justification/i), "INC-9001");
  await user.click(screen.getByRole("button", { name: /raise request/i }));
}

describe("SupportRequestPanel", () => {
  it("cannot raise until a scope is picked and a justification is written", async () => {
    render(<SupportRequestPanel held={null} onGranted={vi.fn()} onReleased={vi.fn()} />);
    expect(screen.getByRole("button", { name: /raise request/i })).toBeDisabled();
  });

  it("raises with the picked scopes and justification", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    raiseSupportRequest.mockResolvedValue({
      request_id: "r1",
      requested_scopes: ["devices:read"],
      expires_at: 1,
    });
    pollSupportRequest.mockResolvedValue({ status: "pending" });
    render(<SupportRequestPanel held={null} onGranted={vi.fn()} onReleased={vi.fn()} />);

    await raise(user);

    expect(raiseSupportRequest).toHaveBeenCalledWith({
      requested_scopes: ["devices:read"],
      justification: "INC-9001",
    });
    expect(await screen.findByText(/waiting for a tenant admin/i)).toBeInTheDocument();
  });

  it("polls until approved, then reports the grant up", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const onGranted = vi.fn();
    raiseSupportRequest.mockResolvedValue({ request_id: "r1", requested_scopes: [], expires_at: 1 });
    pollSupportRequest.mockResolvedValueOnce({ status: "pending" }).mockResolvedValueOnce({
      status: "approved",
      grant_id: "g1",
      credential: "sgr_secret",
    });
    render(<SupportRequestPanel held={null} onGranted={onGranted} onReleased={vi.fn()} />);

    await raise(user);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });

    await waitFor(() => expect(onGranted).toHaveBeenCalledWith({ held: true, grant_id: "g1" }));
  });

  it("stops polling and reports a rejection", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    raiseSupportRequest.mockResolvedValue({ request_id: "r1", requested_scopes: [], expires_at: 1 });
    pollSupportRequest.mockResolvedValue({ status: "rejected" });
    render(<SupportRequestPanel held={null} onGranted={vi.fn()} onReleased={vi.fn()} />);

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

  it("never renders the credential itself, only the grant id, once held", () => {
    render(
      <SupportRequestPanel held={{ held: true, grant_id: "g1" }} onGranted={vi.fn()} onReleased={vi.fn()} />,
    );
    expect(screen.getByText("g1", { exact: false })).toBeInTheDocument();
    expect(screen.queryByText(/sgr_/)).not.toBeInTheDocument();
  });

  it("releases the grant and reports it up", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const onReleased = vi.fn();
    releaseSupportGrant.mockResolvedValue({ released: "g1" });
    render(
      <SupportRequestPanel
        held={{ held: true, grant_id: "g1" }}
        onGranted={vi.fn()}
        onReleased={onReleased}
      />,
    );

    await user.click(screen.getByRole("button", { name: /release grant/i }));

    await waitFor(() => expect(onReleased).toHaveBeenCalled());
  });
});
