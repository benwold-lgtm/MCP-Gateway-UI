// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import type { Session } from "../types";
import { health, ui } from "../tokens";
import { Shell, RailItem } from "./Shell";
import { CatalogConsole } from "./CatalogConsole";

/** The provider plane's shell.
 *
 * ADR-0017 slice 6 removed the act-on-tenant/elevated-grant mechanism this console used to
 * present (`ActOnTenant`, `ElevationPanel`, the live-grant status strip) — `grants.py` and
 * `routers/provider.py` are gone from the BFF, and `require_role` now refuses every
 * provider-plane session on the tenant data plane unconditionally (see `security.py`).
 * ADR-0017's replacement (a support request the provider raises and the tenant approves) is
 * slice 7/8, not yet built — so Devices, Monitoring and Backup are shown but disabled,
 * honestly reflecting that there is currently no path to them, rather than silently
 * vanishing or pretending a grant mechanism still lives here.
 *
 * Catalog is unaffected: curating device types and assigning them to a tenant are
 * provider-plane acts on the provider's own storage (ADR-0020 §2), never a write into any
 * tenant's registry, so it never depended on act-on-tenant in the first place.
 */
type View = "access" | "devices" | "monitoring" | "backup" | "catalog";

export function ProviderConsole({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const [view, setView] = useState<View>("access");

  // Signed in but mapped to nothing: saying so beats every route answering 403.
  const scopes = session.provider_scopes ?? [];

  const rail = (
    <>
      <RailItem label="Access" active={view === "access"} onClick={() => setView("access")} />
      <RailItem
        label="Devices"
        active={false}
        disabled
        hint="not available yet (ADR-0017)"
        onClick={() => {}}
      />
      <RailItem
        label="Monitoring"
        active={false}
        disabled
        hint="not available yet (ADR-0017)"
        onClick={() => {}}
      />
      <RailItem
        label="Backup"
        active={false}
        disabled
        hint="not available yet (ADR-0017)"
        onClick={() => {}}
      />
      {/* Not gated on anything above: curating the catalog and assigning a type to a tenant
          are provider-plane acts on the provider's own storage (ADR-0020 §2), never a write
          into any tenant's registry. */}
      <RailItem label="Catalog" active={view === "catalog"} onClick={() => setView("catalog")} />
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
        <div style={{ display: "grid", gap: 12, maxWidth: 640 }}>
          <p style={{ color: ui.inkSoft }}>
            Reaching a tenant's fleet from the provider console is being rebuilt (ADR-0017): a tenant now
            delegates access by approving a request you raise, rather than this console asserting it. That
            flow has not shipped here yet — Devices, Monitoring and Backup stay disabled until it does.
          </p>
        </div>
      )}
      {/* Unlike the disabled rail items above, not gated on anything — see the module doc. */}
      {view === "catalog" && <CatalogConsole />}
    </Shell>
  );
}
