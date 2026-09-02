// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, it, expect, vi } from "vitest";

// `enrolments` is hoisted rather than left inline because the Support tab's visibility now
// depends on its answer, so tests need to vary it.
const { me, authConfig, enrolments } = vi.hoisted(() => ({
  me: vi.fn(),
  authConfig: vi.fn(),
  enrolments: vi.fn(),
}));

// No active session → api.me() rejects; the app must fall back to the login screen.
vi.mock("../api", () => ({
  api: {
    me,
    overview: vi.fn().mockResolvedValue({ devices: [], counts: {} }),
    logout: vi.fn(),
    login: vi.fn(),
    authConfig,
    support: {
      requests: vi.fn().mockResolvedValue({ requests: [] }),
      grants: vi.fn().mockResolvedValue({ grants: [] }),
      standingConsent: vi.fn().mockResolvedValue({ enabled: false }),
    },
    // The Support tab renders the enrolment panel alongside the inbox (ADR-0024 §10), so
    // this mock has to answer for both — the two are one authority, `support:administer`.
    enrolment: {
      invitations: vi.fn().mockResolvedValue({ invitations: [] }),
      enrolments,
      thisTenant: vi.fn().mockResolvedValue({ tenant_id: "t-1", public_gateway_url: "https://gw.example" }),
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

// A tenant deployment: it has a TENANT_ID, so the provider-relationship screens are relevant
// whether or not a provider is enrolled yet. `catalog_enabled` stays false because most tests
// here are not about the catalog — the two are separate questions, which is why the BFF
// reports them separately.
const CONFIG = {
  oidc_enabled: false,
  password_login: true,
  provider_enabled: false,
  catalog_enabled: false,
  tenancy_configured: true,
};

const SUPPORT_ADMIN = {
  kind: "password",
  plane: "tenant",
  subject: "local:admin",
  role: "admin",
  scopes: ["devices:read", "devices:write", "support:administer"],
  provider_scopes: [],
};

describe("App", () => {
  beforeEach(() => {
    authConfig.mockResolvedValue(CONFIG);
    enrolments.mockReset();
    enrolments.mockResolvedValue({ enrolments: [] });
  });

  it("shows the login screen when there is no session", async () => {
    me.mockRejectedValue(new Error("401"));
    render(<App />);
    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows the Support nav item only for a session holding support:administer (ADR-0017 §7)", async () => {
    me.mockResolvedValue(SUPPORT_ADMIN);
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

  // --- Support on a deployment that has no provider -----------------------------------
  //
  // Holding `support:administer` is not the same as having anything to administer. On a Lite
  // or plain single-tenant stack every section of that tab is permanently empty, because a
  // provider relationship is what fills all four and there is no provider. LR-22's rule one
  // level up: an entry whose every panel answers "none" is worse than no entry.
  //
  // The gate cannot be config alone, and these tests pin why. The support routes relay
  // straight to the gateway and need no TENANT_ID, so an enrolment can outlive the setting —
  // and §10 chose revocation over expiry precisely on the promise that the tenant can always
  // end one. Hiding the tab on config alone would break that promise.

  it("hides Support on a deployment with no tenancy and no enrolment", async () => {
    authConfig.mockResolvedValue({ ...CONFIG, tenancy_configured: false });
    me.mockResolvedValue(SUPPORT_ADMIN);
    render(<App />);

    await screen.findByRole("button", { name: /^devices$/i });
    await waitFor(() => expect(enrolments).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /^support$/i })).not.toBeInTheDocument();
  });

  it("keeps Support when an enrolment exists, even with no tenancy configured", async () => {
    // The stranding case. The console lost (or never had) its TENANT_ID, but a provider is
    // still enrolled on the gateway behind it — and ending that relationship is the one
    // control §10 guarantees. Withholding the tab here would leave the access standing with
    // no way to revoke it from the product.
    authConfig.mockResolvedValue({ ...CONFIG, tenancy_configured: false });
    enrolments.mockResolvedValue({
      enrolments: [
        {
          enrolment_id: "e-1",
          provider_subject: "u-1",
          provider_label: "Acme MSP",
          approved_by: "admin",
          approved_at: 1,
          last_used_at: null,
        },
      ],
    });
    me.mockResolvedValue(SUPPORT_ADMIN);
    render(<App />);

    expect(await screen.findByRole("button", { name: /^support$/i })).toBeInTheDocument();
  });

  it("keeps Support when the enrolment lookup fails, rather than inferring an absence", async () => {
    // Fails open. The cost of guessing wrong is withholding a revocation control from a
    // console whose gateway was merely unreachable for a moment.
    authConfig.mockResolvedValue({ ...CONFIG, tenancy_configured: false });
    enrolments.mockRejectedValue(new Error("gateway down"));
    me.mockResolvedValue(SUPPORT_ADMIN);
    render(<App />);

    expect(await screen.findByRole("button", { name: /^support$/i })).toBeInTheDocument();
  });

  it("does not ask about enrolments at all without support:administer", async () => {
    // A viewer would get a 403 for its trouble, and the answer could not change what is
    // rendered anyway.
    authConfig.mockResolvedValue({ ...CONFIG, tenancy_configured: false });
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
    expect(enrolments).not.toHaveBeenCalled();
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
  it("does not offer Claim from catalog on a lite / single-tenant stack", async () => {
    // The lite edition has no TENANT_ID, so every catalog route fails closed. This button
    // used to be rendered unconditionally, and a home user's first screen answered with
    // "TENANT_ID not configured on this BFF" — a multi-tenancy error naming a variable
    // their edition does not have.
    me.mockResolvedValue({
      kind: "password",
      plane: "tenant",
      subject: "local:admin",
      role: "admin",
      scopes: ["devices:read", "devices:write"],
      provider_scopes: [],
    });
    render(<App />);

    expect(await screen.findByRole("button", { name: /register device/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /claim from catalog/i })).not.toBeInTheDocument();
  });

  it("offers Claim from catalog once the deployment is part of an estate", async () => {
    authConfig.mockResolvedValue({ ...CONFIG, catalog_enabled: true });
    me.mockResolvedValue({
      kind: "password",
      plane: "tenant",
      subject: "local:admin",
      role: "admin",
      scopes: ["devices:read", "devices:write"],
      provider_scopes: [],
    });
    render(<App />);

    expect(await screen.findByRole("button", { name: /claim from catalog/i })).toBeInTheDocument();
  });
});
