// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// ADR-0017 slice 6 removed the act-on-tenant/elevated-grant UI this file used to exercise
// end-to-end (authorize/release/elevate/elevation, the live-grant status strip, the W1/W2/
// W5/W6 tier views reached through an act). None of that exists in `ProviderConsole` any
// more — a provider-plane session has no path to a tenant's fleet at all right now (its
// replacement is ADR-0017 slice 7/8). What this file proves instead: the console says so
// honestly, Devices/Monitoring/Backup are visible-but-disabled rather than hidden, Catalog
// (unrelated, ADR-0020) still works, and the no-mapped-groups message survives unchanged.
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ProviderConsole } from "../components/ProviderConsole";
import type { Session } from "../types";

vi.mock("../api", () => ({
  api: { provider: { catalog: {} } },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

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
    renderConsole({ ...SESSION, provider_scopes: [] });
    expect(screen.getByText(/grant no provider access/i)).toBeInTheDocument();
  });

  it("explains why the tenant data plane is unreachable, on the landing view", () => {
    renderConsole();
    expect(screen.getByText(/being rebuilt/i)).toBeInTheDocument();
  });

  it("keeps Devices/Monitoring/Backup visible but disabled, not hidden", () => {
    // Hiding them would teach nothing about why they are out of reach, and the why is the
    // whole design: there is currently no path to any of them.
    renderConsole();
    for (const label of [/^devices/i, /^monitoring/i, /^backup/i]) {
      const item = screen.getByRole("button", { name: label });
      expect(item).toBeDisabled();
    }
  });

  it("leaves Catalog enabled and reachable", async () => {
    // Curating the catalog and assigning a type to a tenant are provider-plane acts on the
    // provider's own storage (ADR-0020 §2), never a write into any tenant's registry, so
    // this never depended on the removed mechanism.
    renderConsole();
    const catalog = screen.getByRole("button", { name: /^catalog$/i });
    expect(catalog).toBeEnabled();
  });

  it("signs out", async () => {
    const onSignOut = vi.fn();
    const { default: userEvent } = await import("@testing-library/user-event");
    render(<ProviderConsole session={SESSION} onSignOut={onSignOut} />);
    await userEvent.setup().click(screen.getByRole("button", { name: /sign out/i }));
    expect(onSignOut).toHaveBeenCalled();
  });
});
