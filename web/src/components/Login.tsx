// SPDX-License-Identifier: Elastic-2.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { Role } from "../types";

export function Login({ onLogin }: { onLogin: (role: Role) => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const { role } = await api.login(password);
      onLogin(role);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    }
  }

  return (
    <form onSubmit={submit} style={{ maxWidth: 320, margin: "10vh auto", display: "grid", gap: 8 }}>
      <h1>Device MCP Gateway</h1>
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        autoFocus
      />
      <button type="submit">Sign in</button>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
    </form>
  );
}
