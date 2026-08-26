// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0017 §7, slice 8 — the tenant console's own pending-items surface: the inbox, active
// grants, standing consent, and notifications. Four independent panels, tested for the one
// property each shares — approve/reject/revoke act on the right id, and each section reads
// its own failure/empty state honestly rather than collapsing into a blank screen.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { SupportRequestsInbox } from "../components/SupportRequestsInbox";

const { requests, approve, reject, grants, revoke, standingConsent, disableStandingConsent, notifications } =
  vi.hoisted(() => ({
    requests: vi.fn(),
    approve: vi.fn(),
    reject: vi.fn(),
    grants: vi.fn(),
    revoke: vi.fn(),
    standingConsent: vi.fn(),
    disableStandingConsent: vi.fn(),
    notifications: vi.fn(),
  }));

vi.mock("../api", () => ({
  api: {
    support: { requests, approve, reject, grants, revoke, standingConsent, disableStandingConsent },
    notifications,
  },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const PENDING = {
  request_id: "r1",
  provider_subject: "oidc:provider#op1",
  requested_scopes: ["devices:read"],
  justification: "INC-9001: reproducing the fault",
  created_at: 1,
  expires_at: 2,
};

const GRANT = {
  id: "g1",
  provider_subject: "oidc:provider#op1",
  scopes: ["devices:read"],
  issued_at: 1,
  expires_at: 2,
  step_up_verified: false,
  self_issued: false,
};

beforeEach(() => {
  for (const fn of [
    requests,
    approve,
    reject,
    grants,
    revoke,
    standingConsent,
    disableStandingConsent,
    notifications,
  ])
    fn.mockReset();
  requests.mockResolvedValue({ requests: [] });
  grants.mockResolvedValue({ grants: [] });
  standingConsent.mockResolvedValue({ enabled: false });
  notifications.mockResolvedValue({ notifications: [] });
});

describe("SupportRequestsInbox", () => {
  it("says nothing is waiting, rather than an empty blank", async () => {
    render(<SupportRequestsInbox />);
    expect(await screen.findByText(/nothing waiting on a decision/i)).toBeInTheDocument();
  });

  it("shows a pending request's justification and lets an admin approve it", async () => {
    requests.mockResolvedValue({ requests: [PENDING] });
    approve.mockResolvedValue({ grant_id: "g1", expires_at: 2 });
    const user = userEvent.setup();
    render(<SupportRequestsInbox />);

    await screen.findByText(/reproducing the fault/i);
    await user.click(screen.getByRole("button", { name: /^approve$/i }));

    expect(approve).toHaveBeenCalledWith("r1");
  });

  it("rejects a request by its id", async () => {
    requests.mockResolvedValue({ requests: [PENDING] });
    reject.mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(<SupportRequestsInbox />);

    await screen.findByText(/reproducing the fault/i);
    await user.click(screen.getByRole("button", { name: /^reject$/i }));

    expect(reject).toHaveBeenCalledWith("r1");
  });

  it("says no support grants are live, rather than an empty blank", async () => {
    render(<SupportRequestsInbox />);
    expect(await screen.findByText(/no support grants are live/i)).toBeInTheDocument();
  });

  it("revokes an active grant by its id", async () => {
    grants.mockResolvedValue({ grants: [GRANT] });
    revoke.mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(<SupportRequestsInbox />);

    await screen.findByText(/oidc:provider#op1/i);
    await user.click(screen.getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(revoke).toHaveBeenCalledWith("g1"));
  });

  it("renders nothing for standing consent when it is off", async () => {
    render(<SupportRequestsInbox />);
    await screen.findByText(/no support grants are live/i);
    expect(screen.getByText(/every request needs a human decision/i)).toBeInTheDocument();
  });

  it("shows who enabled standing consent and can disable it", async () => {
    standingConsent.mockResolvedValue({
      enabled: true,
      scopes: ["devices:read"],
      enabled_by: "key:admin",
      enabled_at: 1,
      expires_at: 2,
    });
    disableStandingConsent.mockResolvedValue(undefined);
    const user = userEvent.setup();
    render(<SupportRequestsInbox />);

    await screen.findByText(/key:admin/i);
    await user.click(screen.getByRole("button", { name: /^disable$/i }));

    expect(disableStandingConsent).toHaveBeenCalled();
  });

  it("renders nothing for notifications when there are none", async () => {
    render(<SupportRequestsInbox />);
    await screen.findByText(/no support grants are live/i);
    expect(screen.queryByText(/notifications/i)).not.toBeInTheDocument();
  });

  it("shows a notification's message", async () => {
    notifications.mockResolvedValue({
      notifications: [
        {
          id: "n1",
          kind: "break_glass.activated",
          subject: "key:alice",
          message: "Break-glass was used",
          severity: "critical",
        },
      ],
    });
    render(<SupportRequestsInbox />);
    expect(await screen.findByText(/break-glass was used/i)).toBeInTheDocument();
  });
});
