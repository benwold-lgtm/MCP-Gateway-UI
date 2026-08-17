// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError, asElevation, asGrant } from "../api";
import type { ActGrant, AuthConfig, Elevation, Overview, Session, StepUpOutcome } from "../types";
import { ActOnTenant } from "./ActOnTenant";
import { ElevationPanel } from "./ElevationPanel";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";

/** The provider plane's shell (ADR-0013 §4/§8).
 *
 * Composes the act and the elevation on top of it, and owns the one piece of state neither
 * can own alone: what the BFF holds right now. Both panels read that from here rather than
 * fetching independently, because they describe **one** session — an act displayed by one
 * component while another believed a different tenant was live would be the console
 * disagreeing with itself about whose estate is open.
 */
export function ProviderConsole({
  session,
  config,
  onSignOut,
}: {
  session: Session;
  config: AuthConfig | null;
  onSignOut: () => void;
}) {
  const [act, setAct] = useState<ActGrant | null>(null);
  const [elevation, setElevation] = useState<Elevation | null>(null);
  const [outcome, setOutcome] = useState<StepUpOutcome | null>(() => readStepUpOutcome());
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [a, e] = await Promise.all([api.provider.actOnTenant(), api.provider.elevation()]);
      setAct(asGrant(a));
      setElevation(asElevation(e));
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not read provider state");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // A step-up lands back here by full-page navigation, so the outcome arrives in the URL
  // rather than in a response. Strip it once read: it should not survive a reload, be
  // bookmarked, or reappear as a stale "granted" beside an elevation that has since been
  // spent — the grant itself is always re-read from the BFF.
  useEffect(() => {
    if (outcome) window.history.replaceState({}, "", window.location.pathname);
  }, [outcome]);

  // An operator who has signed in but whose directory groups map to nothing gets a session
  // with no provider authority at all. Saying so beats every route answering 403.
  const scopes = session.provider_scopes ?? [];
  if (scopes.length === 0) {
    return (
      <Shell session={session} onSignOut={onSignOut}>
        <p style={{ color: "crimson" }}>
          You are signed in, but your directory groups grant no provider access on this console. Nothing here
          is available until that mapping is in place.
        </p>
      </Shell>
    );
  }

  return (
    <Shell session={session} onSignOut={onSignOut} act={act}>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      <div style={{ display: "grid", gap: 16 }}>
        <ActOnTenant grant={act} onChanged={refresh} />
        <ElevationPanel
          act={act}
          elevation={elevation}
          outcome={outcome}
          stepUpEnabled={config?.step_up_enabled ?? false}
          onChanged={refresh}
          onDismissOutcome={() => setOutcome(null)}
        />
        {/* W1: the tenant's own fleet, reached *through* the act. Gated on the act rather
            than on the plane — a live grant admits a provider session to the tenant data
            plane, capped by the gateway at devices:read/devices:write/metrics:read (§5a).
            When the act ends this unmounts, which is D4's "eject" answer: a screen of a
            customer's data that outlives the authority to see it is indistinguishable from
            a live one. */}
        {act ? <TenantFleet tenant={act.tenant} /> : null}
      </div>
    </Shell>
  );
}

/** Reads what the step-up callback redirected back with. */
export function readStepUpOutcome(search = window.location.search): StepUpOutcome | null {
  const params = new URLSearchParams(search);
  const status = params.get("elevation");
  if (status === "granted") return { status: "granted" };
  if (status === "denied") return { status: "denied", reason: params.get("reason") ?? "unknown" };
  return null;
}

/** The tenant's fleet, seen through a live act (W1, tier 1).
 *
 * The tenant console's own components, unchanged — a provider acting on a customer needs the
 * same views that customer's operators use, and keeping a second copy in sync would be a
 * standing bug. What differs is the frame and the ceiling, not the views.
 *
 * `canWrite` is deliberately **false** pending D2. `devices:write` is inside the gateway's
 * provider ceiling, so this is not the gateway refusing — it is the console declining to
 * hand someone a Delete button for a customer's hardware while that question is open. A
 * ceiling is what the plane may do; a console is what we put a button on, and they need not
 * match. Flip this when D2 is settled, not before.
 */
function TenantFleet({ tenant }: { tenant: string }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setOverview(await api.overview());
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not read this tenant's fleet");
    }
  }, []);

  // Keyed on the tenant so superseding an act re-reads rather than showing the previous
  // customer's fleet under the new tenant's name.
  useEffect(() => {
    setOverview(null);
    setSelected(null);
    void load();
  }, [tenant, load]);

  return (
    <section style={{ border: "1px solid #ddd", borderRadius: 6, padding: "12px 16px" }}>
      <h2 style={{ marginTop: 0, fontSize: "1.05em" }}>{tenant} — devices</h2>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {selected && <DeviceDetail hostname={selected} canWrite={false} onClose={() => setSelected(null)} />}
      {overview ? (
        <DeviceList
          overview={overview}
          canWrite={false}
          onChanged={load}
          onSelect={setSelected}
          onEdit={() => undefined}
        />
      ) : (
        !error && <p style={{ color: "#555" }}>Loading devices…</p>
      )}
    </section>
  );
}

function Shell({
  session,
  onSignOut,
  act,
  children,
}: {
  session: Session;
  onSignOut: () => void;
  act?: ActGrant | null;
  children: React.ReactNode;
}) {
  return (
    <main style={{ maxWidth: 720, margin: "2rem auto", fontFamily: "system-ui, sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          <p style={{ margin: 0, letterSpacing: "0.08em", fontSize: "0.7em", color: "#a15c00" }}>
            PROVIDER CONSOLE
          </p>
          <h1 style={{ margin: 0, fontSize: "1.3em" }}>Device MCP Gateway</h1>
        </div>
        <span>
          <span>{session.name || session.subject}</span> <button onClick={onSignOut}>Sign out</button>
        </span>
      </header>
      {/* A partial answer to D3: whose estate is on screen, stated once, above everything
          reached through the act. The full persistent bar with a countdown is W3. */}
      {act && (
        <p
          style={{
            margin: "10px 0 0",
            padding: "5px 10px",
            background: "#fbf0e0",
            border: "1px solid #a15c00",
            borderRadius: 4,
            fontSize: "0.85em",
            color: "#7a4506",
          }}
        >
          Everything below belongs to <strong>{act.tenant}</strong>, reached through your live act.
        </p>
      )}
      <div style={{ marginTop: 20 }}>{children}</div>
    </main>
  );
}
