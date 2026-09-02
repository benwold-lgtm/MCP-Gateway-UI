// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0024 §10 — the tenant console's half of enrolment: issue an invitation, see who holds
// one, see who is enrolled, end either.
//
// Two properties carry more weight here than the CRUD:
//
//  * the issued code is shown **once, with the fact that it is once stated on screen** — there
//    is no route that re-shows it, so a panel that displayed it like ordinary data would let an
//    admin dismiss a value they cannot get back;
//  * `last_used_at` is rendered **in words, including when it is null**. §10 chose revocation
//    over expiry, which is only safe if a dormant relationship is visible — and "never used" is
//    the value an empty column hides best.
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { EnrolmentPanel } from "../components/EnrolmentPanel";

const { invitations, createInvitation, revokeInvitation, enrolments, revoke, thisTenant } = vi.hoisted(
  () => ({
    invitations: vi.fn(),
    thisTenant: vi.fn(),
    createInvitation: vi.fn(),
    revokeInvitation: vi.fn(),
    enrolments: vi.fn(),
    revoke: vi.fn(),
  }),
);

vi.mock("../api", () => ({
  api: { enrolment: { invitations, createInvitation, revokeInvitation, enrolments, revoke, thisTenant } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const ENROLMENT = {
  enrolment_id: "e-1",
  provider_subject: "u-op-1",
  provider_label: "Acme MSP",
  approved_by: "admin",
  approved_at: 1_700_000_000,
  catalog_url: "https://catalog.example",
  last_used_at: null as number | null,
};

let user: ReturnType<typeof userEvent.setup>;

beforeEach(() => {
  vi.clearAllMocks();
  user = userEvent.setup();
  invitations.mockResolvedValue({ invitations: [] });
  enrolments.mockResolvedValue({ enrolments: [] });
  thisTenant.mockResolvedValue({ tenant_id: "t-1", public_gateway_url: "https://gw.example" });
  createInvitation.mockResolvedValue({
    code: "inv_one-time-secret",
    provider_label: "Acme MSP",
    expires_at: 1_700_003_600,
    created_by: "admin",
  });
  revokeInvitation.mockResolvedValue({});
  revoke.mockResolvedValue({});
});

// --- issuing --------------------------------------------------------------------------------

describe("issuing an invitation", () => {
  it("sends the provider label and shows the code with its one-time warning", async () => {
    render(<EnrolmentPanel />);
    await user.type(await screen.findByLabelText("Provider name"), "Acme MSP");
    await user.click(screen.getByRole("button", { name: /issue invitation/i }));

    await waitFor(() => expect(createInvitation).toHaveBeenCalledWith("Acme MSP"));
    expect(await screen.findByText("inv_one-time-secret")).toBeInTheDocument();
    // The warning is the point: there is no route that re-shows this value.
    expect(screen.getByText(/not shown again/i)).toBeInTheDocument();
  });

  it("will not submit an empty provider label", async () => {
    // The gateway refuses it too — an invitation nobody can attribute is one nobody can safely
    // hand over — but a disabled button says so at the point of the mistake.
    render(<EnrolmentPanel />);
    expect(await screen.findByRole("button", { name: /issue invitation/i })).toBeDisabled();
    expect(createInvitation).not.toHaveBeenCalled();
  });

  it("dismissing the code removes it from the screen", async () => {
    render(<EnrolmentPanel />);
    await user.type(await screen.findByLabelText("Provider name"), "Acme MSP");
    await user.click(screen.getByRole("button", { name: /issue invitation/i }));
    await screen.findByText("inv_one-time-secret");

    await user.click(screen.getByRole("button", { name: /^done$/i }));
    expect(screen.queryByText("inv_one-time-secret")).not.toBeInTheDocument();
  });

  it("reports a refusal instead of silently doing nothing", async () => {
    const { ApiError } = await import("../api");
    createInvitation.mockRejectedValue(new ApiError(400, "provider_label is required"));
    render(<EnrolmentPanel />);
    await user.type(await screen.findByLabelText("Provider name"), "Acme MSP");
    await user.click(screen.getByRole("button", { name: /issue invitation/i }));

    expect(await screen.findByText(/provider_label is required/)).toBeInTheDocument();
  });

  it("refreshes the outstanding list so the new invitation appears without a reload", async () => {
    render(<EnrolmentPanel />);
    await waitFor(() => expect(invitations).toHaveBeenCalledTimes(1));
    await user.type(screen.getByLabelText("Provider name"), "Acme MSP");
    await user.click(screen.getByRole("button", { name: /issue invitation/i }));
    await waitFor(() => expect(invitations).toHaveBeenCalledTimes(2));
  });
});

// --- outstanding invitations ------------------------------------------------------------------

describe("outstanding invitations", () => {
  it("withdraws by code hash and reloads", async () => {
    invitations.mockResolvedValue({
      invitations: [
        { code_hash: "h1", provider_label: "Acme MSP", created_by: "admin", created_at: 1, expires_at: 2 },
      ],
    });
    render(<EnrolmentPanel />);
    await user.click(await screen.findByRole("button", { name: /withdraw/i }));

    await waitFor(() => expect(revokeInvitation).toHaveBeenCalledWith("h1"));
    expect(invitations).toHaveBeenCalledTimes(2);
  });

  it("says nothing is outstanding rather than rendering a blank section", async () => {
    render(<EnrolmentPanel />);
    expect(await screen.findByText(/none waiting to be redeemed/i)).toBeInTheDocument();
  });
});

// --- live relationships -------------------------------------------------------------------

describe("enrolled providers", () => {
  it("states a never-used enrolment in words", async () => {
    // The field §10's revocation-over-expiry trade rests on. An admin scanning for a
    // relationship standing open that nobody has used is looking for exactly this row, and an
    // empty cell is what would hide it.
    enrolments.mockResolvedValue({ enrolments: [ENROLMENT] });
    render(<EnrolmentPanel />);
    expect(await screen.findByText(/never used since it was approved/i)).toBeInTheDocument();
  });

  it("shows a real last-used time when there is one", async () => {
    enrolments.mockResolvedValue({ enrolments: [{ ...ENROLMENT, last_used_at: 1_700_000_500 }] });
    render(<EnrolmentPanel />);
    expect(await screen.findByText(/^last used /i)).toBeInTheDocument();
    expect(screen.queryByText(/never used/i)).not.toBeInTheDocument();
  });

  it("says an enrolment does not expire, so ending one reads as the control it is", async () => {
    enrolments.mockResolvedValue({ enrolments: [ENROLMENT] });
    render(<EnrolmentPanel />);
    expect(await screen.findByText(/does not expire/i)).toBeInTheDocument();
  });

  it("confirms before ending an enrolment, and ends the right one", async () => {
    enrolments.mockResolvedValue({
      enrolments: [ENROLMENT, { ...ENROLMENT, enrolment_id: "e-2", provider_label: "Other MSP" }],
    });
    render(<EnrolmentPanel />);

    await user.click((await screen.findAllByRole("button", { name: /end enrolment/i }))[0]);
    expect(screen.getByText(/loses access immediately/i)).toBeInTheDocument();
    expect(revoke).not.toHaveBeenCalled();

    await user.click(screen.getAllByRole("button", { name: /^end enrolment$/i })[0]);
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("e-1"));
  });

  it("cancelling the confirmation ends nothing", async () => {
    enrolments.mockResolvedValue({ enrolments: [ENROLMENT] });
    render(<EnrolmentPanel />);
    await user.click(await screen.findByRole("button", { name: /end enrolment/i }));
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(revoke).not.toHaveBeenCalled();
  });

  it("reports a failure to revoke instead of appearing to have succeeded", async () => {
    const { ApiError } = await import("../api");
    enrolments.mockResolvedValue({ enrolments: [ENROLMENT] });
    revoke.mockRejectedValue(new ApiError(503, "gateway unreachable"));
    render(<EnrolmentPanel />);
    await user.click(await screen.findByRole("button", { name: /end enrolment/i }));
    await user.click(screen.getAllByRole("button", { name: /^end enrolment$/i })[0]);

    expect(await screen.findByText(/gateway unreachable/)).toBeInTheDocument();
  });

  it("says no provider is enrolled rather than rendering nothing", async () => {
    render(<EnrolmentPanel />);
    expect(await screen.findByText(/no provider is enrolled/i)).toBeInTheDocument();
  });

  it("never renders a credential", async () => {
    // The gateway keeps this tenant's catalog credential behind its own route rather than as a
    // field on the listing. Nothing here should reintroduce it onto a screen left open.
    enrolments.mockResolvedValue({ enrolments: [ENROLMENT] });
    const { container } = render(<EnrolmentPanel />);
    await screen.findByText(/never used/i);
    expect(container.textContent).not.toMatch(/credential/i);
  });
});

// --- what the provider needs from us --------------------------------------------------------
//
// §10's handshake needs three values and this panel used to produce one. The other two lived
// in a ConfigMap, so "invite a provider" handed an admin a code and left them to find a tenant
// id and a reachable gateway address outside the product.

describe("handover details", () => {
  it("shows this tenant's id and public gateway URL beside the invitation form", async () => {
    render(<EnrolmentPanel />);
    expect(await screen.findByText("t-1")).toBeInTheDocument();
    expect(screen.getByText("https://gw.example")).toBeInTheDocument();
  });

  it("names the missing setting rather than showing a guessed address", async () => {
    // The BFF knows an in-cluster gateway URL. Substituting it would look like an answer and
    // fail in the *provider's* console at redemption, naming neither this field nor this
    // tenant — so an unset value is reported as unset.
    thisTenant.mockResolvedValue({ tenant_id: "t-1", public_gateway_url: "" });
    render(<EnrolmentPanel />);
    const list = (await screen.findByText("Tenant id")).closest("dl")!;
    expect(within(list).getByText(/not configured/)).toBeInTheDocument();
    expect(within(list).getByText("PUBLIC_GATEWAY_URL")).toBeInTheDocument();
  });

  it("does not break the rest of the panel when the lookup fails", async () => {
    // A section that cannot load must not take the invitation form down with it — issuing a
    // code is still useful when the console cannot state its own address.
    thisTenant.mockRejectedValue(new Error("nope"));
    render(<EnrolmentPanel />);
    expect(await screen.findByRole("heading", { name: /invite a provider/i })).toBeInTheDocument();
  });
});

// --- a deployment with no provider ------------------------------------------------------------
//
// A Lite or single-tenant stack has no `TENANT_ID` and no `PUBLIC_GATEWAY_URL`, and cannot
// complete this handshake: the provider console requires both alongside the code and will not
// submit without them. Offering the form there mints a one-time credential that is spent on a
// redemption which cannot succeed — and the operator finds out in somebody else's console.

describe("a console that cannot complete the handshake", () => {
  it("withholds the invitation form when neither setting is configured", async () => {
    thisTenant.mockResolvedValue({ tenant_id: "", public_gateway_url: "" });
    render(<EnrolmentPanel />);

    expect(await screen.findByText(/not set up to work with a provider/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Provider name")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue invitation/i })).not.toBeInTheDocument();
  });

  it("withholds it when only one of the two is missing", async () => {
    // Either one missing is enough. The provider needs all three values, so a code issued
    // with half the handover is exactly as unredeemable as one issued with none of it.
    thisTenant.mockResolvedValue({ tenant_id: "t-1", public_gateway_url: "" });
    render(<EnrolmentPanel />);

    expect(await screen.findByText(/not set up to work with a provider/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue invitation/i })).not.toBeInTheDocument();
  });

  it("names only the setting that is actually missing", async () => {
    thisTenant.mockResolvedValue({ tenant_id: "t-1", public_gateway_url: "" });
    render(<EnrolmentPanel />);

    const explanation = (await screen.findByText(/not set up to work with a provider/i)).closest("section")!;
    expect(within(explanation).getByText("PUBLIC_GATEWAY_URL")).toBeInTheDocument();
    expect(within(explanation).queryByText("TENANT_ID")).not.toBeInTheDocument();
  });

  it("still lists and can end an existing enrolment", async () => {
    // §10 chose revocation over expiry. A relationship that already exists has to stay
    // visible and endable from a console whose configuration has since been lost — otherwise
    // withholding the form would take away the control and leave the access standing.
    thisTenant.mockResolvedValue({ tenant_id: "", public_gateway_url: "" });
    enrolments.mockResolvedValue({ enrolments: [ENROLMENT] });
    render(<EnrolmentPanel />);

    expect(await screen.findByText("Acme MSP")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /end enrolment/i }));
    await user.click(screen.getByRole("button", { name: /^end enrolment$/i }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("e-1"));
  });

  it("offers the form when the lookup failed, rather than inferring an absence from an error", async () => {
    // The cost of guessing wrong here is withholding a working control from a console that is
    // configured perfectly well and merely could not reach its own BFF for a moment.
    thisTenant.mockRejectedValue(new Error("nope"));
    render(<EnrolmentPanel />);

    expect(await screen.findByLabelText("Provider name")).toBeInTheDocument();
    expect(screen.queryByText(/not set up to work with a provider/i)).not.toBeInTheDocument();
  });
});
