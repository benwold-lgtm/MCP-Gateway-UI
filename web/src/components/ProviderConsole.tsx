// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { HeldSupportGrant, Overview, Session } from "../types";
import { health, ui } from "../tokens";
import { Shell, RailItem } from "./Shell";
import { CatalogConsole } from "./CatalogConsole";
import { ProviderEnrolment } from "./ProviderEnrolment";
import { SupportRequestPanel } from "./SupportRequestPanel";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";
import { Dashboard } from "./Dashboard";
import { BackupPanel } from "./BackupPanel";

/** The provider plane's shell (ADR-0017 §7).
 *
 * ADR-0017 slice 6 removed the act-on-tenant/elevated-grant mechanism this console used to
 * present (`ActOnTenant`, `ElevationPanel`, the live-grant status strip) — `grants.py` and
 * `routers/provider.py` (the old ones) are gone from the BFF. What replaces it, built here:
 * a support request the operator raises (`SupportRequestPanel`), a tenant admin approves
 * from their own console, and the credential the gateway hands back is what makes Devices/
 * Monitoring/Backup reachable — gated on `heldGrant`, not on anything this console asserts
 * about itself.
 *
 * `canWrite`/`canInvoke` are optimistic once a grant is held, not derived from its actual
 * scopes: this console never learns them (the BFF deliberately does not cache scope detail
 * for a support grant — see `security.py`'s `SessionInfo.support_grant` docstring), so it
 * trusts the same backstop every OIDC tenant session already relies on — the gateway
 * refuses whatever the held credential does not actually cover, on the token it is handed.
 *
 * Catalog is unaffected throughout: curating device types and assigning them to a tenant are
 * provider-plane acts on the provider's own storage (ADR-0020 §2), never a write into any
 * tenant's registry, so it never depended on act-on-tenant in the first place.
 */
type View = "access" | "devices" | "monitoring" | "backup" | "catalog" | "enrolment";

export function ProviderConsole({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const [view, setView] = useState<View>("access");
  const [heldGrant, setHeldGrant] = useState<HeldSupportGrant | null>(null);

  useEffect(() => {
    api.provider
      .currentSupportGrant()
      .then(setHeldGrant)
      .catch(() => setHeldGrant({ held: false }));
  }, []);

  // Losing the grant ejects from anything it was holding open — a screen of a tenant's
  // fleet that outlives the authority to see it is indistinguishable from a live one.
  useEffect(() => {
    setView((v) =>
      !heldGrant?.held && v !== "catalog" && v !== "access" && v !== "enrolment" ? "access" : v,
    );
  }, [heldGrant]);

  // Signed in but mapped to nothing: saying so beats every route answering 403.
  const scopes = session.provider_scopes ?? [];
  const isAdmin = scopes.includes("provider:admin");

  // A monitor has no catalog rail item to click, but state can still arrive there (a
  // session whose scopes narrowed under it, a future deep link). Fall back rather than
  // render a panel whose every fetch 403s.
  useEffect(() => {
    setView((v) => ((v === "catalog" || v === "enrolment") && !isAdmin ? "access" : v));
  }, [isAdmin]);

  const held = heldGrant?.held ?? false;

  const rail = (
    <>
      <RailItem label="Access" active={view === "access"} onClick={() => setView("access")} />
      <RailItem
        label="Devices"
        active={view === "devices"}
        disabled={!held}
        hint={!held ? "needs an approved support grant" : undefined}
        onClick={() => setView("devices")}
      />
      <RailItem
        label="Monitoring"
        active={view === "monitoring"}
        disabled={!held}
        hint={!held ? "needs an approved support grant" : undefined}
        onClick={() => setView("monitoring")}
      />
      <RailItem
        label="Backup"
        active={view === "backup"}
        disabled={!held}
        hint={!held ? "needs an approved support grant" : undefined}
        onClick={() => setView("backup")}
      />
      {/* Not gated on the grant — see the module doc — but it *is* gated on provider:admin:
          every catalog route in the BFF, the reads included, is admin-only
          (`routers/catalog.py`). Rendering it for a monitor produced a rail item whose every
          tab answered 403. */}
      {isAdmin && <RailItem label="Catalog" active={view === "catalog"} onClick={() => setView("catalog")} />}
      {/* Admin-only for the same reason, and gated on nothing else: enrolling a tenant is
          what CREATES the relationship a support grant is later raised within, so requiring
          a grant to reach it would be circular — there is no tenant to raise against yet. */}
      {isAdmin && (
        <RailItem label="Enrolment" active={view === "enrolment"} onClick={() => setView("enrolment")} />
      )}
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
    <Shell brand="SyncGate" eyebrow="PROVIDER CONSOLE" rail={rail} identity={identity}>
      {view === "access" && (
        <SupportRequestPanel
          held={heldGrant}
          providerScopes={scopes}
          onGranted={setHeldGrant}
          onReleased={() => setHeldGrant({ held: false })}
        />
      )}
      {view === "backup" && held && <BackupPanel />}
      {(view === "devices" || view === "monitoring") && held && <TenantViews view={view} />}
      {view === "catalog" && isAdmin && <CatalogConsole />}
      {view === "enrolment" && isAdmin && <ProviderEnrolment />}
    </Shell>
  );
}

/** The tenant's fleet and monitoring, reached through a held support grant.
 *
 * The tenant console's own components, unchanged — a provider helping a customer needs the
 * same views that customer's operators use. `canWrite`/`canInvoke` are optimistic; see the
 * module doc for why this console cannot know the grant's actual scopes and does not try to.
 */
function TenantViews({ view }: { view: "devices" | "monitoring" }) {
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

  useEffect(() => {
    void load();
  }, [load]);

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
              canWrite={true}
              canInvoke={true}
              invokeReason="Running a tool needs a support grant that carries 'tools:call'."
              onClose={() => setSelected(null)}
            />
          )}
          {overview ? (
            <DeviceList
              overview={overview}
              canWrite={true}
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
