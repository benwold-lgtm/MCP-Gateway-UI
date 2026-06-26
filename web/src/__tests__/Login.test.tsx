// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Login } from "../components/Login";

// vi.mock is hoisted above the module, so the mock fns must come from vi.hoisted
// (a plain outer const would be in the temporal dead zone when the factory runs).
const { login, me, authConfig } = vi.hoisted(() => ({
  login: vi.fn(),
  me: vi.fn(),
  authConfig: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { login, me, authConfig },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

describe("Login", () => {
  beforeEach(() => {
    login.mockReset();
    me.mockReset();
    authConfig.mockReset();
    authConfig.mockResolvedValue({ oidc_enabled: false, password_login: true });
  });

  it("renders a password field and a sign-in button", async () => {
    render(<Login onAuthed={vi.fn()} />);
    expect(await screen.findByPlaceholderText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("submits the password and reports the resolved session", async () => {
    login.mockResolvedValue({ role: "admin" });
    me.mockResolvedValue({
      kind: "password",
      subject: "local:admin",
      role: "admin",
      scopes: ["devices:write"],
    });
    const onAuthed = vi.fn();
    render(<Login onAuthed={onAuthed} />);
    await userEvent.type(await screen.findByPlaceholderText("Password"), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(login).toHaveBeenCalledWith("s3cret"));
    await waitFor(() => expect(onAuthed).toHaveBeenCalledWith(expect.objectContaining({ role: "admin" })));
  });

  it("shows an SSO button (and the SSO route) when OIDC is enabled", async () => {
    authConfig.mockResolvedValue({ oidc_enabled: true, password_login: true });
    render(<Login onAuthed={vi.fn()} />);
    const sso = await screen.findByRole("button", { name: /sign in with sso/i });
    expect(sso).toBeInTheDocument();
    // The button is wrapped in a link to the BFF's OIDC login route (full-page nav).
    expect(sso.closest("a")).toHaveAttribute("href", "/auth/oidc/login");
  });

  it("hides the password form when only SSO is configured", async () => {
    authConfig.mockResolvedValue({ oidc_enabled: true, password_login: false });
    render(<Login onAuthed={vi.fn()} />);
    expect(await screen.findByRole("button", { name: /sign in with sso/i })).toBeInTheDocument();
    expect(screen.queryByPlaceholderText("Password")).not.toBeInTheDocument();
  });
});
