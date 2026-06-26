// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

// No active session → api.me() rejects; the app must fall back to the login screen.
vi.mock("../api", () => ({
  api: {
    me: vi.fn().mockRejectedValue(new Error("401")),
    overview: vi.fn(),
    logout: vi.fn(),
    login: vi.fn(),
    authConfig: vi.fn().mockResolvedValue({ oidc_enabled: false, password_login: true }),
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
    render(<App />);
    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});
