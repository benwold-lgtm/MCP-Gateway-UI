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
    // The Support tab renders the enrolment panel alongside the inbox (ADR-0024 §10), so
    // this mock has to answer for both — the two are one authority, `support:administer`.
    enrolment: {
      invitations: vi.fn().mockResolvedValue({ invitations: [] }),
      enrolments: vi.fn().mockResolvedValue({ enrolments: [] }),
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

  // --- Backup on the tenant console (ADR-0011: the registry is the tenant's own data) ---
  //
  // The routes were always mounted on both planes; only the tenant screen was missing, so
  // the capability was reachable with `curl` while the console implied it was not.

  it("offers Backup to a tenant session holding backup:read", async () => {
    me.mockResolvedValue({
      kind: "oidc",
      plane: "tenant",
      subject: "idp:tenantadmin",
      scopes: ["devices:read", "devices:write", "backup:read", "backup:write"],
      provider_scopes: [],
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /^backup$/i }));
    expect(await screen.findByRole("heading", { name: /backup and restore/i })).toBeInTheDocument();
  });

  it("hides Backup from a break-glass admin, whose role is admin but who holds no backup scope", async () => {
    // The case that makes scope-gating rather than role-gating load-bearing. A password
    // session's role IS "admin", but `PASSWORD_ROLE_SCOPES` deliberately withholds every
    // `backup:*` scope because the BFF refuses that session on all four backup routes --
    // it proxies with the stack's admin token. Gating the nav on the role would offer a
    // screen whose every button 403s, which reads as a broken console rather than a
    // deliberate refusal.
    me.mockResolvedValue({
      kind: "password",
      plane: "tenant",
      subject: "local:admin",
      role: "admin",
      scopes: ["devices:read", "devices:write", "metrics:read", "tools:call", "support:administer"],
      provider_scopes: [],
    });
    render(<App />);

    await screen.findByRole("button", { name: /^devices$/i });
    expect(screen.queryByRole("button", { name: /^backup$/i })).not.toBeInTheDocument();
  });

  it("hides Backup from a viewer", async () => {
    me.mockResolvedValue({
      kind: "oidc",
      plane: "tenant",
      subject: "idp:tenantop",
      scopes: ["devices:read", "metrics:read"],
      provider_scopes: [],
    });
    render(<App />);

    await screen.findByRole("button", { name: /^devices$/i });
    expect(screen.queryByRole("button", { name: /^backup$/i })).not.toBeInTheDocument();
  });
});
