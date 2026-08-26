// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";

const { me } = vi.hoisted(() => ({ me: vi.fn() }));

// No active session → api.me() rejects; the app must fall back to the login screen.
vi.mock("../api", () => ({
  api: {
    me,
    overview: vi.fn().mockResolvedValue({ devices: [], counts: {} }),
    logout: vi.fn(),
    login: vi.fn(),
    authConfig: vi.fn().mockResolvedValue({ oidc_enabled: false, password_login: true }),
    support: {
      requests: vi.fn().mockResolvedValue({ requests: [] }),
      grants: vi.fn().mockResolvedValue({ grants: [] }),
      standingConsent: vi.fn().mockResolvedValue({ enabled: false }),
    },
    notifications: vi.fn().mockResolvedValue({ notifications: [] }),
    catalog: { upgrades: vi.fn().mockResolvedValue({ offers: [] }) },
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

import { App } from "../App";

describe("App", () => {
  it("shows the login screen when there is no session", async () => {
    me.mockRejectedValue(new Error("401"));
    render(<App />);
    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows the Support nav item only for a session holding support:administer (ADR-0017 §7)", async () => {
    me.mockResolvedValue({
      kind: "password",
      plane: "tenant",
      subject: "local:admin",
      role: "admin",
      scopes: ["devices:read", "devices:write", "support:administer"],
      provider_scopes: [],
    });
    const user = userEvent.setup();
    render(<App />);

    const support = await screen.findByRole("button", { name: /^support$/i });
    await user.click(support);
    expect(await screen.findByText(/nothing waiting on a decision/i)).toBeInTheDocument();
  });

  it("hides the Support nav item without support:administer", async () => {
    me.mockResolvedValue({
      kind: "password",
      plane: "tenant",
      subject: "local:viewer",
      role: "viewer",
      scopes: ["devices:read"],
      provider_scopes: [],
    });
    render(<App />);

    await screen.findByRole("button", { name: /^devices$/i });
    expect(screen.queryByRole("button", { name: /^support$/i })).not.toBeInTheDocument();
  });
});
