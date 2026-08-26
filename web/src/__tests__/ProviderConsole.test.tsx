// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0017 slice 7/8 — the provider console's own shell: what gates the rail, not the
// raise/poll transaction itself (`SupportRequestPanel.test.tsx` covers that in isolation).
// Slice 6 removed the act-on-tenant/elevated-grant UI this file used to exercise
// end-to-end; what replaces the gate is a held support grant rather than a live act.
import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ProviderConsole } from "../components/ProviderConsole";
import type { HeldSupportGrant, Session } from "../types";

const { currentSupportGrant, listTenants } = vi.hoisted(() => ({
  currentSupportGrant: vi.fn(),
  listTenants: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { provider: { currentSupportGrant, listTenants, catalog: {} } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

// The tenant directory SupportRequestPanel fetches on mount — the panel's own tests
// cover its content; here it just needs to resolve so mounting the console doesn't throw.
beforeEach(() => {
  listTenants.mockReset();
  listTenants.mockResolvedValue({ tenants: [{ tenant_id: "t-1", display_name: "Acme Inc" }] });
});

const SESSION: Session = {
  kind: "oidc",
  plane: "provider",
  subject: "op-14",
  role: null,
  scopes: [],
  provider_scopes: ["provider:admin"],
  name: "Sam Okafor",
};

function renderConsole(session: Session = SESSION) {
  return render(<ProviderConsole session={session} onSignOut={vi.fn()} />);
}

describe("ProviderConsole", () => {
  it("tells an operator whose groups map to nothing, rather than 403ing everywhere", () => {
    currentSupportGrant.mockResolvedValue({ held: false } satisfies HeldSupportGrant);
    renderConsole({ ...SESSION, provider_scopes: [] });
    expect(screen.getByText(/grant no provider access/i)).toBeInTheDocument();
  });

  it("shows the raise-a-request panel on the landing view when nothing is held", async () => {
    currentSupportGrant.mockResolvedValue({ held: false } satisfies HeldSupportGrant);
    renderConsole();
    expect(await screen.findByText(/raise a support request/i)).toBeInTheDocument();
  });

  it("keeps Devices/Monitoring/Backup visible but disabled while nothing is held", async () => {
    // Hiding them would teach nothing about why they are out of reach.
    currentSupportGrant.mockResolvedValue({ held: false } satisfies HeldSupportGrant);
    renderConsole();
    await screen.findByText(/raise a support request/i);
    for (const label of [/^devices/i, /^monitoring/i, /^backup/i]) {
      expect(screen.getByRole("button", { name: label })).toBeDisabled();
    }
  });

  it("enables Devices/Monitoring/Backup once a grant is already held on load", async () => {
    currentSupportGrant.mockResolvedValue({
      held: true,
      grant_id: "g1",
      tenant_id: "t-1",
    } satisfies HeldSupportGrant);
    renderConsole();
    await waitFor(() => {
      for (const label of [/^devices/i, /^monitoring/i, /^backup/i]) {
        expect(screen.getByRole("button", { name: label })).toBeEnabled();
      }
    });
  });

  it("leaves Catalog enabled and reachable regardless of a held grant", async () => {
    // Curating the catalog and assigning a type to a tenant are provider-plane acts on the
    // provider's own storage (ADR-0020 §2), never a write into any tenant's registry.
    currentSupportGrant.mockResolvedValue({ held: false } satisfies HeldSupportGrant);
    renderConsole();
    await screen.findByText(/raise a support request/i);
    expect(screen.getByRole("button", { name: /^catalog$/i })).toBeEnabled();
  });

  it("signs out", async () => {
    currentSupportGrant.mockResolvedValue({ held: false } satisfies HeldSupportGrant);
    const onSignOut = vi.fn();
    const { default: userEvent } = await import("@testing-library/user-event");
    render(<ProviderConsole session={SESSION} onSignOut={onSignOut} />);
    await screen.findByText(/raise a support request/i);
    await userEvent.setup().click(screen.getByRole("button", { name: /sign out/i }));
    expect(onSignOut).toHaveBeenCalled();
  });
});
