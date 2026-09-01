// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ProviderLogin } from "../components/ProviderLogin";
import type { AuthConfig } from "../types";

vi.mock("../api", () => ({
  api: { login: vi.fn(), me: vi.fn() },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const CONFIG: AuthConfig = {
  oidc_enabled: false,
  password_login: true,
  provider_enabled: true,
  catalog_enabled: false,
};

describe("ProviderLogin", () => {
  it("sends SSO to the provider IdP, never the tenant one", () => {
    // The plane is a fact about which IdP authenticated (§3). Pointing this at
    // /auth/oidc/login would produce a tenant-plane session on the provider console —
    // and the BFF would be right to refuse every route, opaquely.
    render(<ProviderLogin config={CONFIG} onAuthed={vi.fn()} />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/auth/provider/login");
  });

  it("marks itself as the provider console before anything is typed", () => {
    // The two consoles are otherwise the same app on the same screen, and an operator
    // about to act inside customers' estates should not have to infer which one they are in.
    render(<ProviderLogin config={CONFIG} onAuthed={vi.fn()} />);
    expect(screen.getByText(/provider console/i)).toBeInTheDocument();
  });

  it("says that signing in grants no tenant access on its own", () => {
    render(<ProviderLogin config={CONFIG} onAuthed={vi.fn()} />);
    expect(screen.getByText(/does not grant access to any tenant/i)).toBeInTheDocument();
  });

  it("labels break-glass as the local login it is", () => {
    // Password login is tenant-plane by construction, so it opens the device console even
    // here. Presenting it as a second way into the provider plane would be a lie the BFF
    // then contradicts with a 403.
    render(<ProviderLogin config={CONFIG} onAuthed={vi.fn()} />);
    expect(screen.getByText(/not the provider plane/i)).toBeInTheDocument();
  });

  it("omits break-glass when the deployment has no local password", () => {
    render(<ProviderLogin config={{ ...CONFIG, password_login: false }} onAuthed={vi.fn()} />);
    expect(screen.queryByPlaceholderText("Password")).not.toBeInTheDocument();
  });
});
