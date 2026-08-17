// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { AuthConfig, Session } from "../types";
import { health, sans, ui } from "../tokens";

/** The provider console's way in (ADR-0013 §2/§3).
 *
 * Deliberately a separate component from `Login`, and deliberately **not** a plane selector
 * inside it. The BFF refuses to start with both IdPs configured, so a deployment is either
 * a tenant console or a provider one; this renders because `/auth/config` said which
 * deployment the browser reached, not because an operator chose a plane from a dropdown. A
 * selector would put the choice back in the request — the exact shape §3 avoids by making
 * the plane a fact about *which IdP authenticated* rather than something a caller asserts.
 *
 * It looks different from the tenant login on purpose. An operator about to act inside
 * customers' estates should be able to tell, before typing anything, which console they are
 * in — the two are otherwise the same app on the same screen.
 */
export function ProviderLogin({
  config,
  onAuthed,
}: {
  config: AuthConfig | null;
  onAuthed: (session: Session) => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Break-glass stays available here (`create_app` keeps it on both planes), but it is not
  // a way into the provider plane: a password login is tenant-plane by construction, so it
  // lands in the ordinary device console. Shown second, and labelled for what it is.
  const showPassword = config?.password_login ?? false;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.login(password);
      onAuthed(await api.me());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    }
  }

  return (
    <div
      style={{
        maxWidth: 360,
        margin: "10vh auto",
        display: "grid",
        gap: 12,
        fontFamily: sans,
        color: ui.ink,
      }}
    >
      <div>
        <p style={{ margin: 0, letterSpacing: "0.08em", fontSize: "0.75em", color: ui.muted }}>
          PROVIDER CONSOLE
        </p>
        <h1 style={{ margin: "2px 0 0" }}>SyncGate</h1>
      </div>

      <p style={{ margin: 0, fontSize: "0.85em", color: ui.inkSoft }}>
        Signing in here does not grant access to any tenant. Acting on a customer is a separate, recorded
        step.
      </p>

      <a href="/auth/provider/login">
        <button type="button" style={{ width: "100%" }}>
          Sign in with the provider directory
        </button>
      </a>

      {showPassword && (
        <>
          <div style={{ textAlign: "center", color: ui.muted, fontSize: "0.85em" }}>
            or use local break-glass access
          </div>
          <form onSubmit={submit} style={{ display: "grid", gap: 8 }}>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Sign in</button>
          </form>
          <p style={{ margin: 0, fontSize: "0.8em", color: ui.muted }}>
            Break-glass is a local login for this stack only — it opens the device console, not the provider
            plane.
          </p>
        </>
      )}

      {error && <p style={{ color: health.fail }}>{error}</p>}
    </div>
  );
}
