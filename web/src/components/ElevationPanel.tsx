// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { ActGrant, Elevation, ProviderScope, StepUpOutcome } from "../types";
import { formatCountdown, useCountdown } from "../useCountdown";
import { health, priv, ui } from "../tokens";
import { Gate } from "./Gate";

/** The two elevated grants and the step-up behind them (ADR-0013 §5a/§8/§11).
 *
 * An elevation is a round trip: this asks, the IdP re-authenticates the operator, and the
 * BFF's callback verifies the `acr` in the *issued* token before anything is recorded. So
 * requesting one is a full-page navigation away and back — not a fetch — and nothing here
 * may render as though authority was obtained by clicking the button.
 *
 * The outcome is read back from the query string the callback redirected to, because a
 * declined step-up is a legitimate, expected result and not an error page: an IdP may
 * decline `acr_values` and issue a perfectly valid token anyway (§11b constraint 2). That
 * case has to say what actually happened.
 */

const CLASSES: { scope: ProviderScope; label: string; what: string }[] = [
  {
    scope: "provider:invoke",
    label: "Invoke a tool",
    what: "Actuates the customer's hardware. Lasts a short window — one debugging session.",
  },
  {
    scope: "provider:credentials",
    label: "Backup / restore",
    what: "Hands back the customer's credentials. Single use: it is spent by the next operation.",
  },
];

const DENIED_REASONS: Record<string, string> = {
  // The one that matters, and the reason the check exists: the IdP returned a valid token
  // without performing the step-up. Naming it as itself is the difference between "try
  // again" and "your directory is not enforcing the second factor you configured".
  step_up_declined:
    "The identity provider did not perform the step-up. It returned a valid sign-in without the required authentication context, so no elevation was recorded.",
  grant_refused:
    "The step-up completed, but the token did not carry a usable grant for this tenant and class.",
  // Not the same as a broken callback, and saying so saves an operator from looking in the
  // wrong place: the directory answered and refused the request, which is normally a
  // configuration fault at the IdP rather than anything about this session.
  idp_refused:
    "The identity provider refused the request before authenticating you — usually because this tenant or grant class is not configured on its side. The exact reason is in the audit record.",
  token_exchange_failed: "The identity provider would not complete the sign-in.",
  state_mismatch: "The step-up did not match the request that started it, so it was refused.",
  invalid_callback: "The step-up came back incomplete and was refused.",
};

export function ElevationPanel({
  act,
  elevation,
  outcome,
  stepUpEnabled,
  onChanged,
  onDismissOutcome,
}: {
  act: ActGrant | null;
  elevation: Elevation | null;
  outcome: StepUpOutcome | null;
  stepUpEnabled: boolean;
  onChanged: () => void | Promise<void>;
  onDismissOutcome: () => void;
}) {
  const [scope, setScope] = useState<ProviderScope>("provider:invoke");
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const left = useCountdown(elevation?.expires_at);

  async function elevate(e: React.FormEvent) {
    e.preventDefault();
    if (!act) return;
    setBusy(true);
    setError(null);
    try {
      const { authorization_url } = await api.provider.elevate(act.tenant, scope, justification.trim());
      // A real navigation. The IdP will not render in a fetch, and the session cookie has
      // to be present when the callback lands — so the console leaves and comes back.
      window.location.assign(authorization_url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start the step-up");
      setBusy(false);
    }
  }

  async function end() {
    setBusy(true);
    try {
      await api.provider.endElevation();
      await onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not end the elevation");
    } finally {
      setBusy(false);
    }
  }

  if (!stepUpEnabled) {
    return (
      <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
        <h2
          style={{
            marginTop: 0,
            fontSize: "1.05em",
            color: ui.ink,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Gate open={elevation != null} size={20} />
          Elevated access
        </h2>
        <p style={{ margin: 0, color: ui.muted }}>
          Not offered on this deployment: no step-up context is configured, so an elevation could not be
          verified even if it were requested.
        </p>
      </section>
    );
  }

  const selected = CLASSES.find((c) => c.scope === scope);

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <h2
        style={{
          marginTop: 0,
          fontSize: "1.05em",
          color: ui.ink,
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <Gate open={elevation != null} size={20} />
        Elevated access
      </h2>

      {outcome?.status === "denied" && (
        <div
          role="alert"
          style={{
            border: `1px solid ${health.fail}`,
            borderRadius: 4,
            padding: "8px 12px",
            marginBottom: 12,
          }}
        >
          <strong>No elevation was granted.</strong>{" "}
          {DENIED_REASONS[outcome.reason] ?? "The step-up did not complete."}{" "}
          <button onClick={onDismissOutcome} style={{ marginLeft: 4 }}>
            Dismiss
          </button>
        </div>
      )}

      {elevation ? (
        // Single use is stated as a *state*, not a footnote. The two classes behave
        // differently at the moment they are used — one survives the call, one does not —
        // and an operator holding the credentials grant is one operation away from having
        // nothing, which is not something to discover from a 403.
        <div style={{ display: "grid", gap: 8 }}>
          <p style={{ margin: 0 }}>
            <strong>{elevation.scope}</strong> on <strong>{elevation.tenant}</strong>
            <span aria-live="polite" style={{ color: left != null && left < 60 ? health.fail : priv.ink }}>
              {" "}
              — expires in {left != null ? formatCountdown(left) : "…"}
            </span>
          </p>
          <p style={{ margin: 0, fontSize: "0.85em", color: elevation.single_use ? priv.base : ui.muted }}>
            {elevation.single_use
              ? "Single use — the next operation spends it. Re-entering needs another step-up."
              : "Usable for the rest of this window."}
          </p>
          <div>
            <button onClick={end} disabled={busy}>
              End elevation
            </button>
          </div>
        </div>
      ) : !act ? (
        <p style={{ margin: 0, color: ui.muted }}>
          Authorize an act on a tenant first — an elevation sits on top of one.
        </p>
      ) : (
        <form onSubmit={elevate} style={{ display: "grid", gap: 8 }}>
          <p style={{ margin: 0, color: ui.muted, fontSize: "0.9em" }}>
            Requires re-authentication with your directory. On <strong>{act.tenant}</strong>.
          </p>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>What for</span>
            <select value={scope} onChange={(e) => setScope(e.target.value as ProviderScope)}>
              {CLASSES.map((c) => (
                <option key={c.scope} value={c.scope}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
          <p style={{ margin: 0, fontSize: "0.85em", color: ui.muted }}>{selected?.what}</p>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Why (recorded)</span>
            <textarea
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              rows={2}
              placeholder="what you are about to do, and why"
            />
          </label>
          <div>
            <button type="submit" disabled={busy || !justification.trim()}>
              Step up and elevate
            </button>
          </div>
        </form>
      )}

      {error && <p style={{ color: health.fail, marginBottom: 0 }}>{error}</p>}
    </section>
  );
}
