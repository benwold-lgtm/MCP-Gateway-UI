// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { ActGrant } from "../types";
import { health, ui } from "../tokens";

/** Acquiring an act-on-tenant grant (ADR-0013 §4/§8).
 *
 * Only acquisition. The *live* grant — its countdown and its End act control — belongs to the
 * persistent bar in the console shell (W3), because an operator several screens into a device
 * list still needs both, and a panel they have scrolled past cannot provide them. Splitting it
 * this way also removes the duplicate "Acting on X" that appeared when the bar was added.
 *
 * Two properties of the mechanism are rendered rather than left implicit, because an operator
 * who cannot see them will assume the opposite:
 *
 *  * **One at a time.** Authorizing a second tenant drops the first, so the form says which act
 *    it will end rather than letting an operator discover it by finding themselves detached
 *    from the tenant they were working on.
 *  * **The justification is mandatory and unrecoverable.** It goes into a hash-chained,
 *    append-only record and is never echoed back, so this is the only moment it can be written.
 */
export function ActOnTenant({
  grant,
  onChanged,
}: {
  grant: ActGrant | null;
  onChanged: () => void | Promise<void>;
}) {
  const [tenant, setTenant] = useState("");
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function authorize(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.provider.authorize(tenant.trim(), justification.trim());
      setTenant("");
      setJustification("");
      await onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not authorize");
    } finally {
      setBusy(false);
    }
  }

  const supersedes = grant && tenant.trim() && tenant.trim() !== grant.tenant ? grant.tenant : null;

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <h2 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>Act on tenant</h2>

      {!grant && (
        <p style={{ margin: "0 0 8px", color: ui.muted }}>
          Not acting on any tenant. Provider sign-in alone reaches no customer stack.
        </p>
      )}

      <form onSubmit={authorize} style={{ display: "grid", gap: 8 }}>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Tenant</span>
          <input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="tenant id" />
        </label>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Why (recorded)</span>
          <textarea
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            rows={2}
            placeholder="ticket, incident or request this act is for"
          />
        </label>
        {supersedes && (
          <p style={{ margin: 0, color: ui.act, fontSize: "0.85em" }}>
            This ends the current act on <strong>{supersedes}</strong> — one tenant at a time.
          </p>
        )}
        <div>
          <button type="submit" disabled={busy || !tenant.trim() || !justification.trim()}>
            {grant ? "Authorize (replaces current act)" : "Authorize"}
          </button>
        </div>
      </form>

      {/* An error is a failure state, not a privilege state — same channel as a failing device. */}
      {error && <p style={{ color: health.fail, marginBottom: 0 }}>{error}</p>}
    </section>
  );
}
