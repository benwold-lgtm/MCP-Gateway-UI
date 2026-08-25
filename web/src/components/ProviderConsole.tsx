// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError, asElevation, asGrant } from "../api";
import type { ActGrant, AuthConfig, Elevation, Overview, Session, StepUpOutcome } from "../types";
import { formatCountdown, useCountdown } from "../useCountdown";
import { health, priv, ui } from "../tokens";
import { Shell, RailItem, StatusItem } from "./Shell";
import { Gate } from "./Gate";
import { readStepUpOutcome } from "../stepUpOutcome";
import { ActOnTenant } from "./ActOnTenant";
import { ElevationPanel } from "./ElevationPanel";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";
import { Dashboard } from "./Dashboard";
import { BackupExport } from "./BackupExport";
import { BackupRestore } from "./BackupRestore";

/** The provider plane's shell (ADR-0013 §4/§8).
 *
 * Owns the one piece of state no panel can own alone: what the BFF holds right now. Everything
 * else reads it from here, because they describe **one** session — an act displayed by one
 * component while another believed a different tenant was live would be the console disagreeing
 * with itself about whose estate is open.
 */
type View = "access" | "devices" | "monitoring" | "backup";

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
  const [view, setView] = useState<View>("access");

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

  // Losing the act ejects you from anything it was holding open. Leaving a customer's device
  // list on screen after the authority to see it expired is the state ADR-0013 §4 exists to
  // prevent, and a stale view is indistinguishable from a live one.
  useEffect(() => {
    if (!act) setView("access");
  }, [act]);

  // A step-up lands back here by full-page navigation, so the outcome arrives in the URL rather
  // than in a response. Strip it once read: it should not survive a reload, be bookmarked, or
  // reappear as a stale "granted" beside an elevation that has since been spent.
  useEffect(() => {
    if (outcome) window.history.replaceState({}, "", window.location.pathname);
  }, [outcome]);

  // Signed in but mapped to nothing: saying so beats every route answering 403.
  const scopes = session.provider_scopes ?? [];

  // The rail *is* the tier model. Everything behind an act stays visible but disabled, with
  // the reason attached — a console that hid what you cannot yet reach would teach nothing
  // about why, and the "why" here is the whole design.
  const rail = (
    <>
      <RailItem label="Access" active={view === "access"} onClick={() => setView("access")} />
      <RailItem
        label="Devices"
        active={view === "devices"}
        disabled={!act}
        hint={!act ? "needs a live act" : undefined}
        onClick={() => setView("devices")}
      />
      <RailItem
        label="Monitoring"
        active={view === "monitoring"}
        disabled={!act}
        hint={!act ? "needs a live act" : undefined}
        onClick={() => setView("monitoring")}
      />
      {/* Tier 2. Gated on the act like the others rather than on the elevation, deliberately:
          the panel itself explains what a step-up buys, and a rail entry that vanished until
          you already held the grant would teach nothing about why it exists. */}
      <RailItem
        label="Backup"
        active={view === "backup"}
        disabled={!act}
        hint={!act ? "needs a live act" : undefined}
        onClick={() => setView("backup")}
      />
    </>
  );

  const identity = (
    <div style={{ display: "grid", gap: 5 }}>
      <span>{session.name || session.subject}</span>
      <button onClick={onSignOut} style={{ justifySelf: "start" }}>
        Sign out
      </button>
    </div>
  );

  if (scopes.length === 0) {
    return (
      <Shell brand="SyncGate" eyebrow="PROVIDER CONSOLE" rail={null} identity={identity}>
        <p style={{ color: health.fail }}>
          You are signed in, but your directory groups grant no provider access on this console. Nothing here
          is available until that mapping is in place.
        </p>
      </Shell>
    );
  }

  return (
    <Shell
      brand="SyncGate"
      eyebrow="PROVIDER CONSOLE"
      rail={rail}
      identity={identity}
      status={<StatusStrip act={act} elevation={elevation} onChanged={refresh} />}
    >
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {view === "access" && (
        <div style={{ display: "grid", gap: 16, maxWidth: 640 }}>
          <ActOnTenant grant={act} onChanged={refresh} />
          <ElevationPanel
            act={act}
            elevation={elevation}
            outcome={outcome}
            stepUpEnabled={config?.step_up_enabled ?? false}
            onChanged={refresh}
            onDismissOutcome={() => setOutcome(null)}
          />
        </div>
      )}
      {/* Tier 1 views are gated on the act, not the plane. When the act ends they unmount —
          a screen of a customer's data that outlives the authority to see it is
          indistinguishable from a live one. */}
      {view === "backup" && act && <BackupViews tenant={act.tenant} />}
      {(view === "devices" || view === "monitoring") && act && (
        <TenantViews tenant={act.tenant} view={view} elevation={elevation} />
      )}
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
 *
 * `canInvoke` is the opposite case, and the contrast is the point: `tools:call` is **outside**
 * the provider ceiling, reachable only through a live, step-up-backed `provider:invoke`
 * elevation (§5a/§8). So the Run button appears exactly while that elevation is held — which
 * is the design being visible, not a permission being computed here. The BFF refuses without
 * it, and the gateway refuses again on the token it is handed.
 */
function TenantViews({
  tenant,
  view,
  elevation,
}: {
  tenant: string;
  view: "devices" | "monitoring";
  elevation: Elevation | null;
}) {
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
    <section>
      {error && <p style={{ color: health.fail }}>{error}</p>}

      {view === "monitoring" ? (
        <Dashboard />
      ) : (
        <>
          {selected && (
            <DeviceDetail
              hostname={selected}
              canWrite={false}
              canInvoke={elevation?.scope === "provider:invoke"}
              invokeReason="Running a tool on a customer's device needs a live 'provider:invoke' elevation — acquire one from Access."
              onClose={() => setSelected(null)}
            />
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

/** Export and restore (W6, ADR-0013 §5b/§8, gate removed by ADR-0018 §6).
 *
 * No elevation any more: this used to sit behind `provider:credentials`, single-use, spent
 * by the first of export-or-restore. That grant is removed — the gateway no longer stores a
 * credential dump a backup could disclose, so an ordinary act-on-tenant session is the whole
 * requirement, the same as every other tenant-plane view.
 */
function BackupViews({ tenant }: { tenant: string }) {
  return (
    <section style={{ display: "grid", gap: 4, maxWidth: 760 }}>
      <h2 style={{ margin: 0, fontSize: "1.15em", color: ui.ink }}>Backup and restore · {tenant}</h2>
      <BackupExport />
      <BackupRestore />
    </section>
  );
}

/** The status strip's contents (W3).
 *
 * The live grant's home. It carries the countdown and the End act control on every view
 * reached through the act, because an operator three screens into a device list needs both and
 * cannot see a panel they have scrolled past.
 *
 * Coloured with the act channel, not the privilege one: the spec reserves indigo for
 * elevation and step-up, and spending it here would stop it meaning "you are holding elevated
 * authority right now".
 */
function StatusStrip({
  act,
  elevation,
  onChanged,
}: {
  act: ActGrant | null;
  elevation: Elevation | null;
  onChanged: () => void | Promise<void>;
}) {
  const left = useCountdown(act?.expires_at);
  const elevLeft = useCountdown(elevation?.expires_at);
  const [busy, setBusy] = useState(false);

  // The countdown renders from the server's `expires_at`, but the *authority* is the server's
  // too — so at zero we re-read rather than hide the grant locally. A console that quietly
  // stopped displaying an expired grant would be guessing about state the BFF owns.
  const expired = left === 0;
  useEffect(() => {
    if (expired) void onChanged();
  }, [expired, onChanged]);

  // The same treatment for the elevation, which needs it for a second reason: an elevation is
  // what puts a Run button on a customer's device, so an expired one left on screen is an
  // affordance the operator no longer has. Re-read rather than hide it locally — the BFF owns
  // the state, and a console that quietly dropped it would be guessing.
  const elevExpired = elevLeft === 0;
  useEffect(() => {
    if (elevExpired) void onChanged();
  }, [elevExpired, onChanged]);

  const urgent = left != null && left < 60;

  // Nothing held: say so in the strip rather than leaving it blank. An empty strip reads as
  // "not loaded yet"; this reads as "you currently reach nothing", which is the true state.
  if (!act) {
    return (
      <>
        <Gate open={false} />
        <StatusItem label="ACCESS">no live act — no tenant reachable</StatusItem>
      </>
    );
  }

  return (
    <>
      <StatusItem label="ACTING ON">
        <strong>{act.tenant}</strong>
      </StatusItem>
      <StatusItem label="ENDS IN">
        <span aria-live="polite" style={{ color: urgent ? health.fail : ui.inkSoft }}>
          {left != null ? formatCountdown(left) : "…"}
        </span>
      </StatusItem>
      {/* The gate is always mounted so it can be *seen* closing. A badge that unmounts on
          expiry shows nothing at the one moment worth showing — and a single-use grant is
          spent by the next operation, whether or not anyone was watching the panel. */}
      <Gate open={elevation != null} />
      {/* The only indigo in the console, and only while an elevation is actually live. Its
          scarcity is its meaning: if it is on screen, you are holding elevated authority. */}
      {elevation && (
        <StatusItem label="ELEVATED">
          <span style={{ color: priv.base, fontWeight: 600 }}>
            {elevation.scope.replace("provider:", "")}
            {elevation.single_use ? " · single use" : ""}
            {elevLeft != null ? ` · ${formatCountdown(elevLeft)}` : ""}
          </span>
        </StatusItem>
      )}
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
        style={{ marginLeft: "auto" }}
      >
        End act
      </button>
    </>
  );
}
