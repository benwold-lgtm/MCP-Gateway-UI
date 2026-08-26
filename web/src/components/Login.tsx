// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { AuthConfig, Session } from "../types";
import { health, ui } from "../tokens";

export function Login({ onAuthed }: { onAuthed: (session: Session) => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [config, setConfig] = useState<AuthConfig | null>(null);

  // Ask the BFF which login methods are available, so SSO only shows when configured.
  useEffect(() => {
    api
      .authConfig()
      .then(setConfig)
      // Fallback when /auth/config is unreachable: offer the local password and nothing
      // else. `provider_enabled: false` is the honest value here rather than a guess —
      // App already decided this is a tenant console before rendering Login at all, and a
      // provider console that failed to say so must not be inferred into existence.
      .catch(() =>
        setConfig({
          oidc_enabled: false,
          password_login: true,
          provider_enabled: false,
        }),
      );
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.login(password);
      // Resolve the full session (subject + scopes) from the BFF after authenticating.
      onAuthed(await api.me());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    }
  }

  const showPassword = config?.password_login ?? true;
  const showSso = config?.oidc_enabled ?? false;

  return (
    <div style={{ maxWidth: 320, margin: "10vh auto", display: "grid", gap: 12 }}>
      <h1>Device MCP Gateway</h1>

      {showSso && (
        // A full-page navigation (not fetch) so the browser follows the IdP redirect; the
        // BFF sets the session cookie and bounces back to the app, where boot-time me()
        // picks it up.
        <a href="/auth/oidc/login">
          <button type="button" style={{ width: "100%" }}>
            Sign in with SSO
          </button>
        </a>
      )}

      {showSso && showPassword && (
        <div style={{ textAlign: "center", color: ui.muted, fontSize: "0.85em" }}>or sign in locally</div>
      )}

      {showPassword && (
        <form onSubmit={submit} style={{ display: "grid", gap: 8 }}>
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
          />
          <button type="submit">Sign in</button>
        </form>
      )}

      {error && <p style={{ color: health.fail }}>{error}</p>}
    </div>
  );
}
