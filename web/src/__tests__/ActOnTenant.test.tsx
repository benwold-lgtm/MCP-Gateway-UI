// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The tenant picker. The BFF's own suite already proves what the estate *is*; what is
// untested until here is whether an operator can see the two things the list cannot say on
// its own — that a tenant they are entitled to may still be unreachable from this console,
// and that the list is a suggestion rather than a gate.
//
// The load-bearing test is `keeps free entry even when the directory published a list`.
// Every other assertion here describes rendering; that one describes the security boundary,
// because a picker that only offered its own list would have quietly made the console an
// authorization point — the thing ADR-0013 §11c puts on the gateway precisely because the
// console is the side that chose the tenant.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ActOnTenant } from "../components/ActOnTenant";
import type { Estate } from "../types";

const { authorize, tenants } = vi.hoisted(() => ({ authorize: vi.fn(), tenants: vi.fn() }));

vi.mock("../api", () => ({
  api: { provider: { authorize, tenants } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const WHY = "INC-5120: fleet poller recovery check";

function renderPanel(estate: Estate, grant: Parameters<typeof ActOnTenant>[0]["grant"] = null) {
  tenants.mockResolvedValue(estate);
  const onChanged = vi.fn();
  render(<ActOnTenant grant={grant} onChanged={onChanged} />);
  return { onChanged };
}

/** Fill the justification and submit — the two steps every authorization needs. */
async function authorizeWith(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByPlaceholderText(/ticket, incident/i), WHY);
  await user.click(screen.getByRole("button", { name: /^authorize$/i }));
}

describe("ActOnTenant", () => {
  beforeEach(() => {
    authorize.mockReset();
    tenants.mockReset();
    authorize.mockResolvedValue({ id: "g1", tenant: "acme", granted_at: 0, expires_at: 0 });
  });

  it("offers the directory's estate as a list", async () => {
    renderPanel({ entitled: ["acme", "globex"], served: "acme" });
    expect(await screen.findByRole("radio", { name: /acme/ })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /globex/ })).toBeInTheDocument();
  });

  it("marks which tenant this console actually serves", async () => {
    // The gap the list cannot express on its own. Both are real entitlements; only one has
    // a gateway behind it, and an operator who cannot see that difference discovers it as a
    // 403 after writing a justification.
    renderPanel({ entitled: ["acme", "globex"], served: "acme" });
    expect(await screen.findByRole("radio", { name: /acme.*served here/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /globex.*not served here/i })).toBeInTheDocument();
  });

  it("warns before the click that an unserved tenant reaches nothing", async () => {
    renderPanel({ entitled: ["acme", "globex"], served: "acme" });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("radio", { name: /globex/ }));
    expect(screen.getByText(/recorded but reaches no devices/i)).toBeInTheDocument();
    // ...and it is still allowed. The act is legitimate and audited; only its reach is nil.
    await authorizeWith(user);
    await waitFor(() => expect(authorize).toHaveBeenCalledWith("globex", WHY));
  });

  it("says nothing about reach for the tenant it does serve", async () => {
    renderPanel({ entitled: ["acme", "globex"], served: "acme" });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("radio", { name: /acme/ }));
    expect(screen.queryByText(/reaches no devices/i)).not.toBeInTheDocument();
  });

  it("keeps free entry even when the directory published a list", async () => {
    // **The one that matters.** The estate is a snapshot from sign-in and the gateway is the
    // authority, so an operator must be able to name a tenant the list does not contain. A
    // picker that refused would strand anyone whose entitlement changed mid-session — and
    // would put the decision on the side that cannot be trusted to make it.
    renderPanel({ entitled: ["acme"], served: "acme" });
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText("tenant id"), "initech");
    await authorizeWith(user);
    await waitFor(() => expect(authorize).toHaveBeenCalledWith("initech", WHY));
  });

  it("explains an unpublished estate as a missing list, not a revoked one", async () => {
    // `null` means the IdP said nothing. Reporting it as "you are entitled to no tenants"
    // sends the operator to ask for access they may already have; the real fix is a mapper.
    renderPanel({ entitled: null, served: "acme" });
    expect(await screen.findByText(/did not publish a tenant list/i)).toBeInTheDocument();
    expect(screen.queryByText(/lists no tenants for you/i)).not.toBeInTheDocument();
  });

  it("explains an empty estate as the directory having answered", async () => {
    renderPanel({ entitled: [], served: "acme" });
    expect(await screen.findByText(/lists no tenants for you/i)).toBeInTheDocument();
    expect(screen.queryByText(/did not publish a tenant list/i)).not.toBeInTheDocument();
  });

  it("falls back to free entry when the estate cannot be read", async () => {
    // A failed read is not an empty estate. The operator keeps working; the gateway still
    // decides.
    tenants.mockRejectedValue(new Error("network"));
    render(<ActOnTenant grant={null} onChanged={vi.fn()} />);
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText("tenant id"), "acme");
    await authorizeWith(user);
    await waitFor(() => expect(authorize).toHaveBeenCalledWith("acme", WHY));
  });

  it("still refuses to authorize without a justification", async () => {
    // Selecting from a list is one click, so it is exactly where the mandatory field is
    // easiest to forget. It is the only record of why a customer's stack was touched.
    renderPanel({ entitled: ["acme"], served: "acme" });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("radio", { name: /acme/ }));
    expect(screen.getByRole("button", { name: /^authorize$/i })).toBeDisabled();
  });

  it("says which act a new one replaces, picked from the list", async () => {
    renderPanel(
      { entitled: ["acme", "globex"], served: "acme" },
      {
        id: "g0",
        tenant: "acme",
        granted_at: 0,
        expires_at: 0,
      },
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("radio", { name: /globex/ }));
    expect(screen.getByText(/ends the current act on/i)).toHaveTextContent("acme");
  });

  it("reads the estate once, not on every render", async () => {
    // It is stamped at login from the ID token and cannot change while the session lives,
    // so re-reading it would be polling a constant.
    renderPanel({ entitled: ["acme"], served: "acme" });
    await screen.findByRole("radio", { name: /acme/ });
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/ticket, incident/i), WHY);
    expect(tenants).toHaveBeenCalledTimes(1);
  });
});
