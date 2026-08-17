// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError, asElevation, asGrant } from "../api";
import type { ActGrant, AuthConfig, Elevation, Overview, Session, StepUpOutcome } from "../types";
import { formatCountdown, useCountdown } from "../useCountdown";
import { health, sans, ui } from "../tokens";
import { readStepUpOutcome } from "../stepUpOutcome";
import { ActOnTenant } from "./ActOnTenant";
import { ElevationPanel } from "./ElevationPanel";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";
import { Dashboard } from "./Dashboard";

/** The provider plane's shell (ADR-0013 §4/§8).
 *
 * Owns the one piece of state no panel can own alone: what the BFF holds right now. Everything
 * else reads it from here, because they describe **one** session — an act displayed by one
 * component while another believed a different tenant was live would be the console disagreeing
 * with itself about whose estate is open.
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

  // A step-up lands back here by full-page navigation, so the outcome arrives in the URL rather
  // than in a response. Strip it once read: it should not survive a reload, be bookmarked, or
  // reappear as a stale "granted" beside an elevation that has since been spent.
  useEffect(() => {
    if (outcome) window.history.replaceState({}, "", window.location.pathname);
  }, [outcome]);

  // Signed in but mapped to nothing: saying so beats every route answering 403.
  const scopes = session.provider_scopes ?? [];
  if (scopes.length === 0) {
    return (
      <Shell session={session} onSignOut={onSignOut}>
        <p style={{ color: health.fail }}>
          You are signed in, but your directory groups grant no provider access on this console. Nothing here
          is available until that mapping is in place.
        </p>
      </Shell>
    );
  }

  return (
    <Shell session={session} onSignOut={onSignOut} act={act} onChanged={refresh}>
      {error && <p style={{ color: health.fail }}>{error}</p>}
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
        {/* Tier 1: the tenant's own estate, reached *through* the act and gated on it rather
            than on the plane. When the act ends this unmounts — a screen of a customer's data
            that outlives the authority to see it is indistinguishable from a live one. */}
        {act ? <TenantViews tenant={act.tenant} /> : null}
      </div>
    </Shell>
  );
}

/** The tenant's fleet and monitoring, seen through a live act (W1 + W2, tier 1).
 *
 * The tenant console's own components, unchanged. A provider acting on a customer needs the
 * same views that customer's operators use; keeping a second copy in sync would be a standing
 * bug. What differs is the frame and the ceiling, not the views.
 *
 * `canWrite` is deliberately **false** pending the open decision on device writes.
 * `devices:write` is inside the gateway's provider ceiling, so this is not the gateway
 * refusing — it is the console declining to hand someone a Delete button for a customer's
 * hardware while that question is open. A ceiling is what the plane may do; a console is what
 * we put a button on, and they need not match.
 */
function TenantViews({ tenant }: { tenant: string }) {
  const [tab, setTab] = useState<"devices" | "monitoring">("devices");
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
    setTab("devices");
    void load();
  }, [tenant, load]);

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "baseline", marginBottom: 10 }}>
        <h2 style={{ margin: 0, fontSize: "1.05em", color: ui.ink }}>{tenant}</h2>
        <nav style={{ display: "flex", gap: 6 }}>
          <button onClick={() => setTab("devices")} disabled={tab === "devices"}>
            Devices
          </button>
          {/* metrics:read is already inside the provider ceiling, so monitoring needs no
              elevation — it is the same tier as the device list. */}
          <button onClick={() => setTab("monitoring")} disabled={tab === "monitoring"}>
            Monitoring
          </button>
        </nav>
      </div>

      {error && <p style={{ color: health.fail }}>{error}</p>}

      {tab === "monitoring" ? (
        <Dashboard />
      ) : (
        <>
          {selected && (
            <DeviceDetail hostname={selected} canWrite={false} onClose={() => setSelected(null)} />
          )}
          {overview ? (
            <DeviceList
              overview={overview}
              canWrite={false}
              onChanged={load}
              onSelect={setSelected}
              onEdit={() => undefined}
            />
          ) : (
            !error && <p style={{ color: ui.muted }}>Loading devices…</p>
          )}
        </>
      )}
    </section>
  );
}

/** The persistent act bar (W3).
 *
 * The live grant's home. It carries the countdown and the End act control on every view
 * reached through the act, because an operator three screens into a device list needs both and
 * cannot see a panel they have scrolled past.
 *
 * Coloured with the act channel, not the privilege one: the spec reserves indigo for
 * elevation and step-up, and spending it here would stop it meaning "you are holding elevated
 * authority right now".
 */
function ActBar({ act, onChanged }: { act: ActGrant; onChanged: () => void | Promise<void> }) {
  const left = useCountdown(act.expires_at);
  const [busy, setBusy] = useState(false);

  // The countdown renders from the server's `expires_at`, but the *authority* is the server's
  // too — so at zero we re-read rather than hide the grant locally. A console that quietly
  // stopped displaying an expired grant would be guessing about state the BFF owns.
  const expired = left === 0;
  useEffect(() => {
    if (expired) void onChanged();
  }, [expired, onChanged]);

  const urgent = left != null && left < 60;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
        flexWrap: "wrap",
        margin: "10px 0 0",
        padding: "6px 12px",
        background: ui.actSoft,
        border: `1px solid ${ui.act}`,
        borderRadius: 4,
        fontSize: "0.87em",
        color: ui.ink,
      }}
    >
      <span>
        Acting on <strong>{act.tenant}</strong> — everything below is that customer&apos;s estate.
      </span>
      <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span aria-live="polite" style={{ color: urgent ? health.fail : ui.inkSoft }}>
          ends in {left != null ? formatCountdown(left) : "…"}
        </span>
        <button
          onClick={async () => {
            setBusy(true);
            try {
              await api.provider.release();
              await onChanged();
            } finally {
              setBusy(false);
            }
          }}
          disabled={busy}
        >
          End act
        </button>
      </span>
    </div>
  );
}

function Shell({
  session,
  onSignOut,
  act,
  onChanged,
  children,
}: {
  session: Session;
  onSignOut: () => void;
  act?: ActGrant | null;
  onChanged?: () => void | Promise<void>;
  children: React.ReactNode;
}) {
  return (
    <main style={{ maxWidth: 760, margin: "2rem auto", fontFamily: sans, color: ui.ink }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          {/* Chrome, not privilege — so it takes the structural colour. Indigo here would
              dilute the one signal the spec reserves for holding elevated authority. */}
          <p style={{ margin: 0, letterSpacing: "0.08em", fontSize: "0.7em", color: ui.muted }}>
            PROVIDER CONSOLE
          </p>
          <h1 style={{ margin: 0, fontSize: "1.3em" }}>SyncGate</h1>
        </div>
        <span>
          <span>{session.name || session.subject}</span> <button onClick={onSignOut}>Sign out</button>
        </span>
      </header>
      {act && onChanged && <ActBar act={act} onChanged={onChanged} />}
      <div style={{ marginTop: 20 }}>{children}</div>
    </main>
  );
}
