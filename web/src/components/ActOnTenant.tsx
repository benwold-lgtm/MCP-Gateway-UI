// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { ActGrant, Estate } from "../types";
import { health, ui } from "../tokens";

/** Acquiring an act-on-tenant grant (ADR-0013 §4/§8).
 *
 * Only acquisition. The *live* grant — its countdown and its End act control — belongs to the
 * persistent bar in the console shell (W3), because an operator several screens into a device
 * list still needs both, and a panel they have scrolled past cannot provide them. Splitting it
 * this way also removes the duplicate "Acting on X" that appeared when the bar was added.
 *
 * Three properties of the mechanism are rendered rather than left implicit, because an operator
 * who cannot see them will assume the opposite:
 *
 *  * **One at a time.** Authorizing a second tenant drops the first, so the form says which act
 *    it will end rather than letting an operator discover it by finding themselves detached
 *    from the tenant they were working on.
 *  * **The justification is mandatory and unrecoverable.** It goes into a hash-chained,
 *    append-only record and is never echoed back, so this is the only moment it can be written.
 *  * **Entitled is not the same as reachable.** A deployment serves one tenant; an act on any
 *    other is granted, recorded, and then refused by the data plane. That gap is invisible
 *    until it bites, so the list names it in advance.
 *
 * The estate is **navigation, not authorization.** ADR-0013 §11c puts the tenant intersection
 * on the gateway, because the console is the side that chose the tenant — so this list can
 * change what is offered and never what is accepted, and free entry stays available even when
 * the directory published a list. A picker that refused what it had not listed would be the
 * caller validating its own request, and would strand an operator whose entitlement changed
 * after they signed in.
 */

/** Sentinel for the free-entry row. Not a tenant id — the shape rule (`^[a-z0-9]…`) rejects
 *  the empty string, so it can never collide with a real one. */
const OTHER = "";

export function ActOnTenant({
  grant,
  onChanged,
}: {
  grant: ActGrant | null;
  onChanged: () => void | Promise<void>;
}) {
  const [estate, setEstate] = useState<Estate | null>(null);
  const [choice, setChoice] = useState<string>(OTHER);
  const [typed, setTyped] = useState("");
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetched once. The estate is stamped at login from the ID token and cannot change while
  // the session lives, so re-reading it on every grant change would be polling a constant.
  useEffect(() => {
    let live = true;
    api.provider
      .tenants()
      .then((e) => live && setEstate(e))
      // A failed read is not an empty estate. Falling back to free entry keeps the operator
      // working; claiming they are entitled to nothing would be inventing an answer.
      .catch(() => live && setEstate(null));
    return () => {
      live = false;
    };
  }, []);

  const tenant = (choice === OTHER ? typed : choice).trim();

  async function authorize(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.provider.authorize(tenant, justification.trim());
      setChoice(OTHER);
      setTyped("");
      setJustification("");
      await onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not authorize");
    } finally {
      setBusy(false);
    }
  }

  const listed = estate?.entitled ?? null;
  const served = estate?.served ?? null;
  const supersedes = grant && tenant && tenant !== grant.tenant ? grant.tenant : null;
  // Only claimed when this console actually knows what it serves. With `served` unknown we
  // say nothing rather than warn about a mismatch we cannot establish.
  const unreachable = tenant !== "" && served !== null && tenant !== served;

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <h2 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>Act on tenant</h2>

      {!grant && (
        <p style={{ margin: "0 0 8px", color: ui.muted }}>
          Not acting on any tenant. Provider sign-in alone reaches no customer stack.
        </p>
      )}

      <form onSubmit={authorize} style={{ display: "grid", gap: 8 }}>
        <fieldset style={{ border: 0, margin: 0, padding: 0, display: "grid", gap: 4 }}>
          <legend style={{ fontSize: "0.85em", color: ui.inkSoft, padding: 0 }}>Tenant</legend>

          {listed?.map((t) => (
            <TenantChoice
              key={t}
              tenant={t}
              selected={choice === t}
              served={served === t}
              onSelect={() => setChoice(t)}
            />
          ))}

          {/* Always offered, including alongside a full list. The directory's answer is a
              snapshot from sign-in time, and the gateway — not this form — is what decides. */}
          <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input type="radio" name="tenant" checked={choice === OTHER} onChange={() => setChoice(OTHER)} />
            <span style={{ color: ui.ink }}>{listed?.length ? "Another tenant" : "Tenant"}</span>
            <input
              value={typed}
              onChange={(e) => {
                setTyped(e.target.value);
                setChoice(OTHER);
              }}
              placeholder="tenant id"
              aria-label="Tenant id"
            />
          </label>

          <EstateNote listed={listed} />
        </fieldset>

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

        {/* Stated before the click, not discovered after it. The act is real and audited;
            what it reaches is not, and an operator who authorized it deserves to know which
            of those two they are getting. */}
        {unreachable && (
          <p style={{ margin: 0, color: ui.muted, fontSize: "0.85em" }}>
            This console serves <strong>{served}</strong>. An act on <strong>{tenant}</strong> is recorded but
            reaches no devices from here — one console serves one tenant until multi-gateway routing lands.
          </p>
        )}

        <div>
          <button type="submit" disabled={busy || !tenant || !justification.trim()}>
            {grant ? "Authorize (replaces current act)" : "Authorize"}
          </button>
        </div>
      </form>

      {/* An error is a failure state, not a privilege state — same channel as a failing device. */}
      {error && <p style={{ color: health.fail, marginBottom: 0 }}>{error}</p>}
    </section>
  );
}

/** One row of the estate, carrying whether this console can actually reach it.
 *
 * Reachability is deliberately **not** in the health channel: `health` means device state,
 * and spending its vocabulary on "which tenant is this deployment" would make a served tenant
 * and an online device read as the same kind of fact. Words instead of a glyph, for the same
 * reason — a fourth encoding to memorise buys nothing a two-word label does not.
 */
function TenantChoice({
  tenant,
  selected,
  served,
  onSelect,
}: {
  tenant: string;
  selected: boolean;
  served: boolean;
  onSelect: () => void;
}) {
  return (
    <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <input type="radio" name="tenant" checked={selected} onChange={onSelect} />
      <span style={{ color: ui.ink }}>{tenant}</span>
      <span
        style={{
          fontSize: "0.72em",
          letterSpacing: "0.04em",
          textTransform: "uppercase",
          color: served ? ui.act : ui.muted,
        }}
      >
        {served ? "served here" : "not served here"}
      </span>
    </label>
  );
}

/** Why the list looks the way it does.
 *
 * `null` and `[]` are different operator situations with different remedies, and the whole
 * reason the BFF keeps them apart is so this sentence can differ. Collapsing them would tell
 * an operator whose IdP simply lacks a mapper that their entitlement had been revoked.
 */
function EstateNote({ listed }: { listed: string[] | null }) {
  if (listed === null) {
    return (
      <p style={{ margin: "4px 0 0", color: ui.muted, fontSize: "0.85em" }}>
        Your directory did not publish a tenant list on this sign-in, so enter the tenant id. Access is
        unaffected — the gateway checks entitlement either way.
      </p>
    );
  }
  if (listed.length === 0) {
    return (
      <p style={{ margin: "4px 0 0", color: ui.muted, fontSize: "0.85em" }}>
        Your directory lists no tenants for you. You can still name one, but expect it to be refused until the
        entitlement is granted.
      </p>
    );
  }
  return (
    <p style={{ margin: "4px 0 0", color: ui.muted, fontSize: "0.85em" }}>
      From your directory entitlement, as of sign-in.
    </p>
  );
}
