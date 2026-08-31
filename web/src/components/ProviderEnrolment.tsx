// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { RedeemedEnrolment } from "../types";
import { health, ui } from "../tokens";

/** Enrol a tenant by redeeming the invitation it issued (ADR-0024 §10/§11).
 *
 * The provider half of the handshake `EnrolmentPanel` starts in the tenant's own console.
 * The BFF route this calls has existed since #57; nothing in the browser ever reached it, so
 * enrolling a tenant was a documented `curl` and nothing an operator could do here. That is
 * the same class of gap as ADR-0017 §7b's — a server plane and a browser plane that were
 * never asked to agree — arriving from the opposite direction: a capability with no surface,
 * rather than a surface with no capability.
 *
 * **Admin-only, matching the route.** `routers/enrolment.py` gates redemption on
 * `provider:admin`. A monitor gets no rail item, for the reason the Catalog rail learned the
 * hard way (LR-22): a rail entry whose every action answers 403 is worse than no entry.
 *
 * **Four fields, and none of them is guessable.** All four come from the tenant out of band —
 * that is what makes the handover deliberate. The tenant id is the one worth care: a typo
 * mints a catalog credential for one tenant and installs it against another, which the BFF
 * catches by comparing what the gateway reports about itself against what was typed. The
 * form says so rather than leaving the operator to discover it through a 409.
 */
export function ProviderEnrolment() {
  const [code, setCode] = useState("");
  const [gatewayUrl, setGatewayUrl] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<RedeemedEnrolment | null>(null);
  const [error, setError] = useState<string | null>(null);

  const ready = code.trim() !== "" && gatewayUrl.trim() !== "" && tenantId.trim() !== "";

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const result = await api.provider.enrolment.redeem({
        code: code.trim(),
        gateway_url: gatewayUrl.trim(),
        tenant_id: tenantId.trim(),
        ...(displayName.trim() ? { display_name: displayName.trim() } : {}),
      });
      setDone(result);
      // Cleared on success only. A failed redemption is very often a typo in ONE field, and
      // wiping the other three would make the retry harder than the first attempt — while an
      // invitation that succeeded is spent, so leaving it on screen invites a second try that
      // can only fail.
      setCode("");
      setGatewayUrl("");
      setTenantId("");
      setDisplayName("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not enrol this tenant");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: "grid", gap: 20, maxWidth: 720, marginTop: 20 }}>
      <section>
        <h3 style={{ marginBottom: 4 }}>Enrol a tenant</h3>
        <p style={{ margin: "0 0 12px", color: ui.muted, fontSize: "0.9em" }}>
          A tenant administrator issues an invitation in their own console, under Support, and hands you the
          code along with their gateway address and tenant id. Redeeming it here records the tenant, issues
          its catalog credential and installs this console&apos;s credential for its gateway — in one act.
        </p>

        <form onSubmit={submit} style={{ display: "grid", gap: 10 }}>
          <label style={{ display: "grid", gap: 4 }}>
            Invitation code
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="inv_…"
              autoComplete="off"
              spellCheck={false}
            />
          </label>

          <label style={{ display: "grid", gap: 4 }}>
            Tenant gateway URL
            <input
              value={gatewayUrl}
              onChange={(e) => setGatewayUrl(e.target.value)}
              placeholder="https://gateway.tenant.example"
              autoComplete="off"
              spellCheck={false}
            />
            <span style={{ color: ui.muted, fontSize: "0.85em" }}>
              The gateway itself, not the tenant&apos;s console — a console answers on every path and would
              look reachable whether or not the gateway is.
            </span>
          </label>

          <label style={{ display: "grid", gap: 4 }}>
            Tenant id
            <input
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="t-…"
              autoComplete="off"
              spellCheck={false}
            />
            <span style={{ color: ui.muted, fontSize: "0.85em" }}>
              Checked against what the gateway reports about itself. If they disagree nothing is enrolled — a
              credential minted for the wrong tenant is refused before it is installed, not after.
            </span>
          </label>

          <label style={{ display: "grid", gap: 4 }}>
            Display name <span style={{ color: ui.muted, fontSize: "0.85em" }}>(optional)</span>
            <input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Tenant One"
              autoComplete="off"
            />
          </label>

          <button type="submit" disabled={!ready || busy} style={{ justifySelf: "start" }}>
            {busy ? "Enrolling…" : "Enrol tenant"}
          </button>
        </form>

        {error && (
          <p role="alert" style={{ color: health.fail, marginTop: 12 }}>
            {error}
          </p>
        )}

        {done && (
          <div role="status" style={{ marginTop: 12 }}>
            <p style={{ color: health.ok, margin: "0 0 4px" }}>
              Enrolled <strong>{done.tenant_id}</strong>. It is now in the estate and can be selected under
              Access.
            </p>
            <p style={{ margin: 0, color: ui.muted, fontSize: "0.9em" }}>
              Approved by {done.approved_by || "the tenant"} · enrolment {done.enrolment_id}
            </p>
            <p style={{ margin: "8px 0 0", color: ui.muted, fontSize: "0.85em" }}>
              No credential is shown because none is yours to keep: this console&apos;s credential for that
              gateway went straight into the catalog. To end the relationship, the tenant revokes the
              enrolment from their own console — that is the only control it has, and it takes effect on the
              provider&apos;s next request.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
