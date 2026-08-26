// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { UpgradeOffer } from "../types";
import { health, ui } from "../tokens";

/** ADR-0020 §4, slice 5: non-blocking, never scheduled, never forced. A claimed device
 * whose pinned version differs from what's currently curated, with a diff between the two
 * versions' DECLARED tool sets — never a live measurement, since the catalog has no
 * base_url to probe. Renders nothing when there's nothing to offer and nothing when the
 * check itself fails, rather than a banner that nags on every load; a failed check is
 * quiet here on purpose (it is not a fleet-health signal, and the device list above already
 * has its own error surface for anything that actually matters operationally).
 */
export function UpgradeOffers() {
  const [offers, setOffers] = useState<UpgradeOffer[] | null>(null);

  const load = useCallback(() => {
    api.catalog
      .upgrades()
      .then(({ offers }) => setOffers(offers))
      .catch(() => setOffers(null));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (!offers || offers.length === 0) return null;

  return (
    <section
      style={{
        border: `1px solid ${ui.rule}`,
        borderRadius: 8,
        padding: "12px 16px",
        margin: "12px 0",
        background: "#fff",
      }}
    >
      <h3 style={{ marginTop: 0 }}>Catalog upgrades available</h3>
      <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
        {offers.map((o) => (
          <UpgradeOfferRow key={o.hostname} offer={o} onAccepted={load} />
        ))}
      </ul>
    </section>
  );
}

function UpgradeOfferRow({ offer, onAccepted }: { offer: UpgradeOffer; onAccepted: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      await api.catalog.acceptUpgrade(offer.hostname, offer.device_type_id, offer.current_version);
      onAccepted();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not accept this upgrade");
      setBusy(false);
    }
  }

  return (
    <li style={{ borderTop: `1px solid ${ui.rule}`, paddingTop: 8 }}>
      <div>
        <strong>{offer.hostname}</strong> — {offer.slug}: v{offer.claimed_version} → v{offer.current_version}
        {offer.diff?.breaking && (
          <span style={{ color: health.fail, marginLeft: 8, fontSize: "0.85em" }}>breaking change</span>
        )}
      </div>
      {offer.diff === null ? (
        <p style={{ margin: "4px 0 0", color: ui.muted, fontSize: "0.85em" }}>
          No declared tool set to compare — the diff isn't available for this offer.
        </p>
      ) : offer.diff.added.length + offer.diff.removed.length + offer.diff.changed.length === 0 ? (
        <p style={{ margin: "4px 0 0", color: ui.muted, fontSize: "0.85em" }}>No tool changes.</p>
      ) : (
        <p style={{ margin: "4px 0 0", color: ui.inkSoft, fontSize: "0.85em" }}>
          {offer.diff.added.length > 0 && <>+{offer.diff.added.join(", ")} </>}
          {offer.diff.removed.length > 0 && <>-{offer.diff.removed.join(", ")} </>}
          {offer.diff.changed.length > 0 && <>~{offer.diff.changed.join(", ")}</>}
        </p>
      )}
      {error && <p style={{ margin: "4px 0 0", color: health.fail, fontSize: "0.85em" }}>{error}</p>}
      <button onClick={() => void accept()} disabled={busy} style={{ marginTop: 6 }}>
        Accept v{offer.current_version}
      </button>
    </li>
  );
}
