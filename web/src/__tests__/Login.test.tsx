// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { Login } from "../components/Login";

const login = vi.fn();

vi.mock("../api", () => ({
  api: { login: (pw: string) => login(pw) },
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
  beforeEach(() => login.mockReset());

  it("renders a password field and a sign-in button", () => {
    render(<Login onLogin={vi.fn()} />);
    expect(screen.getByPlaceholderText("Password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("submits the password and reports the resolved role", async () => {
    login.mockResolvedValue({ role: "admin" });
    const onLogin = vi.fn();
    render(<Login onLogin={onLogin} />);
    await userEvent.type(screen.getByPlaceholderText("Password"), "s3cret");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(login).toHaveBeenCalledWith("s3cret"));
    await waitFor(() => expect(onLogin).toHaveBeenCalledWith("admin"));
  });
});
