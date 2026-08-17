// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { ActGrant } from "../types";
import { formatCountdown, useCountdown } from "../useCountdown";

/** Acquire, display and end an act-on-tenant grant (ADR-0013 §4/§8).
 *
 * The everyday motion of the provider plane, and the one this whole design exists to keep
 * from becoming ambient. Three properties of the mechanism are rendered rather than left
 * implicit, because an operator who cannot see them will assume the opposite:
 *
 *  * **One at a time.** The session holds a single grant; authorizing a second tenant drops
 *    the first. So when something is held, the form says which act it will end — instead of
 *    an operator discovering it by finding themselves detached from the tenant they were on.
 *  * **The window is absolute.** There is no extend button, because the BFF has no extend
 *    route: `authorize` always mints a new grant with a new id and a new justification
 *    (§8 — "renewal is a new act, not an extension"). The countdown running out is not a
 *    session timeout to be topped up; it is the act ending.
 *  * **The justification is mandatory and unrecoverable.** It goes into a hash-chained,
 *    append-only record and is never echoed back, so this is the only moment it can be
 *    written.
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
  const left = useCountdown(grant?.expires_at);

  // The countdown is rendered from the server's `expires_at`, but the *authority* is the
  // server's too — so when it hits zero we re-read rather than hide the grant locally. A
  // console that quietly stopped displaying an expired grant would be guessing about state
  // the BFF is the only owner of.
  const expired = grant != null && left === 0;
  useEffect(() => {
    if (expired) void onChanged();
  }, [expired, onChanged]);

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

  async function release() {
    setBusy(true);
    setError(null);
    try {
      await api.provider.release();
      await onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not release");
    } finally {
      setBusy(false);
    }
  }

  const supersedes = grant && tenant.trim() && tenant.trim() !== grant.tenant ? grant.tenant : null;

  return (
    <section style={{ border: "1px solid #ddd", borderRadius: 6, padding: "12px 16px" }}>
      <h2 style={{ marginTop: 0, fontSize: "1.05em" }}>Act on tenant</h2>

      {grant ? (
        <div style={{ display: "grid", gap: 8 }}>
          <p style={{ margin: 0 }}>
            Acting on <strong>{grant.tenant}</strong>{" "}
            <span aria-live="polite" style={{ color: left != null && left < 60 ? "crimson" : "#555" }}>
              — ends in {left != null ? formatCountdown(left) : "…"}
            </span>
          </p>
          <div>
            <button onClick={release} disabled={busy}>
              End act
            </button>
          </div>
        </div>
      ) : (
        <p style={{ margin: "0 0 8px", color: "#555" }}>
          Not acting on any tenant. Provider sign-in alone reaches no customer stack.
        </p>
      )}

      <form onSubmit={authorize} style={{ display: "grid", gap: 8, marginTop: 12 }}>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em" }}>Tenant</span>
          <input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="tenant id" />
        </label>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em" }}>Why (recorded)</span>
          <textarea
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            rows={2}
            placeholder="ticket, incident or request this act is for"
          />
        </label>
        {supersedes && (
          <p style={{ margin: 0, color: "#a15c00", fontSize: "0.85em" }}>
            This ends the current act on <strong>{supersedes}</strong> — one tenant at a time.
          </p>
        )}
        <div>
          <button type="submit" disabled={busy || !tenant.trim() || !justification.trim()}>
            {grant ? "Authorize (replaces current act)" : "Authorize"}
          </button>
        </div>
      </form>

      {error && <p style={{ color: "crimson", marginBottom: 0 }}>{error}</p>}
    </section>
  );
}
