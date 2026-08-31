// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0024 §10/§11 — the provider console's half of enrolment.
//
// The BFF route has existed since #57 and nothing in the browser ever called it, so enrolling
// a tenant was a documented `curl`. These tests pin the surface that was missing, and two
// properties beyond the form working:
//
//  * the rail entry is **admin-only, in both directions** — asserting only that a monitor
//    cannot see it would pass just as well if the feature were wired nowhere at all, which is
//    exactly how the gap being fixed here survived four merged PRs;
//  * a redemption shows **no credential**, because none is the operator's to keep. §11 records
//    the provider's gateway credential straight into the catalog precisely so there is no
//    value for a human to paste, and a panel that displayed one would reintroduce the manual
//    step the section exists to remove.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ProviderEnrolment } from "../components/ProviderEnrolment";
import { ProviderConsole } from "../components/ProviderConsole";

const { redeem, currentSupportGrant, listTenants } = vi.hoisted(() => ({
  redeem: vi.fn(),
  currentSupportGrant: vi.fn(),
  listTenants: vi.fn(),
}));

vi.mock("../api", () => ({
  api: {
    provider: {
      enrolment: { redeem },
      currentSupportGrant,
      listTenants,
      releaseSupportGrant: vi.fn(),
      raiseSupportRequest: vi.fn(),
    },
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

const REDEEMED = {
  tenant_id: "t-abc123",
  enrolment_id: "e-9",
  approved_by: "tenant-admin",
  approved_at: 1_700_000_000,
  gateway_url: "https://gw.tenant.example",
  recorded: true,
};

async function fillTheForm(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText(/invitation code/i), "inv_abc");
  await user.type(screen.getByLabelText(/tenant gateway url/i), "https://gw.tenant.example");
  await user.type(screen.getByLabelText(/tenant id/i), "t-abc123");
}

describe("ProviderEnrolment", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    redeem.mockResolvedValue(REDEEMED);
  });

  it("sends exactly what the operator was handed out of band", async () => {
    const user = userEvent.setup();
    render(<ProviderEnrolment />);
    await fillTheForm(user);
    await user.type(screen.getByLabelText(/display name/i), "Tenant One");

    await user.click(screen.getByRole("button", { name: /enrol tenant/i }));

    await waitFor(() => expect(redeem).toHaveBeenCalledTimes(1));
    expect(redeem).toHaveBeenCalledWith({
      code: "inv_abc",
      gateway_url: "https://gw.tenant.example",
      tenant_id: "t-abc123",
      display_name: "Tenant One",
    });
  });

  it("will not submit until all three required fields are present", async () => {
    const user = userEvent.setup();
    render(<ProviderEnrolment />);
    const submit = screen.getByRole("button", { name: /enrol tenant/i });
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText(/invitation code/i), "inv_abc");
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText(/tenant gateway url/i), "https://gw.tenant.example");
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText(/tenant id/i), "t-abc123");
    expect(submit).toBeEnabled();
  });

  it("omits display_name rather than sending an empty one", async () => {
    const user = userEvent.setup();
    render(<ProviderEnrolment />);
    await fillTheForm(user);

    await user.click(screen.getByRole("button", { name: /enrol tenant/i }));

    await waitFor(() => expect(redeem).toHaveBeenCalledTimes(1));
    expect(redeem.mock.calls[0][0]).not.toHaveProperty("display_name");
  });

  it("shows no credential on success — none is the operator's to keep", async () => {
    const user = userEvent.setup();
    render(<ProviderEnrolment />);
    await fillTheForm(user);
    await user.click(screen.getByRole("button", { name: /enrol tenant/i }));

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/t-abc123/);
    expect(status.textContent).not.toMatch(/enr_|cat_/);
  });

  it("clears the form only on success, so a typo can be corrected in place", async () => {
    const user = userEvent.setup();
    redeem.mockRejectedValueOnce(Object.assign(new Error("no such tenant"), { status: 409 }));
    render(<ProviderEnrolment />);
    await fillTheForm(user);

    await user.click(screen.getByRole("button", { name: /enrol tenant/i }));
    await screen.findByRole("alert");
    // The invitation is single-use and the operator has one shot at the other three fields;
    // wiping them on failure would make the retry harder than the first attempt.
    expect(screen.getByLabelText(/tenant id/i)).toHaveValue("t-abc123");
    expect(screen.getByLabelText(/invitation code/i)).toHaveValue("inv_abc");

    redeem.mockResolvedValueOnce(REDEEMED);
    await user.click(screen.getByRole("button", { name: /enrol tenant/i }));
    await screen.findByRole("status");
    expect(screen.getByLabelText(/tenant id/i)).toHaveValue("");
  });

  it("surfaces the BFF's refusal rather than a generic failure", async () => {
    const user = userEvent.setup();
    const { ApiError } = await import("../api");
    redeem.mockRejectedValueOnce(
      new ApiError(409, "the gateway at https://gw.tenant.example reports tenant 't-other'"),
    );
    render(<ProviderEnrolment />);
    await fillTheForm(user);

    await user.click(screen.getByRole("button", { name: /enrol tenant/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/reports tenant 't-other'/);
  });
});

describe("the Enrolment rail entry", () => {
  const session = (scopes: string[]) => ({
    authenticated: true as const,
    plane: "provider" as const,
    subject: "op-1",
    name: "Op One",
    provider_scopes: scopes,
  });

  beforeEach(() => {
    vi.clearAllMocks();
    currentSupportGrant.mockResolvedValue({ held: false });
    listTenants.mockResolvedValue({ tenants: [] });
  });

  it("is offered to a provider:admin", async () => {
    // The direction that actually catches the bug this file exists for. A test asserting only
    // that a monitor cannot see the rail passes identically when the feature is wired nowhere
    // — which is the state the console was in through four merged PRs.
    render(<ProviderConsole session={session(["provider:admin"]) as never} onSignOut={() => {}} />);
    expect(await screen.findByRole("button", { name: /^enrolment$/i })).toBeInTheDocument();
  });

  it("is not offered to a provider:monitor, whose every redemption would 403", async () => {
    render(<ProviderConsole session={session(["provider:monitor"]) as never} onSignOut={() => {}} />);
    await screen.findByRole("button", { name: /^access$/i });
    expect(screen.queryByRole("button", { name: /^enrolment$/i })).not.toBeInTheDocument();
  });

  it("reaches the panel without a support grant — enrolling is what creates the relationship", async () => {
    // Requiring a grant here would be circular: there is no tenant to raise a request against
    // until one has been enrolled.
    const user = userEvent.setup();
    render(<ProviderConsole session={session(["provider:admin"]) as never} onSignOut={() => {}} />);

    await user.click(await screen.findByRole("button", { name: /^enrolment$/i }));

    expect(await screen.findByRole("button", { name: /enrol tenant/i })).toBeInTheDocument();
  });
});
