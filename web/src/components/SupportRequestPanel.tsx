// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api";
import type { HeldSupportGrant, TenantSummary } from "../types";
import { health, ui } from "../tokens";

/** The tenant vocabulary a provider operator may request (ADR-0017 §7).
 *
 * Deliberately narrower than the gateway's own grantable range, which also includes
 * `backup:*`: a support grant reaching a tenant's backup archive is a heavier-weight case
 * than the everyday "help me debug a device" request this panel is for. An operator who
 * genuinely needs it is not blocked — the gateway still accepts a raise naming it — this
 * panel just does not make it one checkbox away from the routine ones.
 */
const OFFERED_SCOPES = ["devices:read", "devices:write", "tools:call", "metrics:read"] as const;

const POLL_INTERVAL_MS = 3000;

type Phase =
  | { kind: "idle" }
  | { kind: "raising" }
  | { kind: "pending"; requestId: string; tenantId: string }
  | { kind: "rejected" }
  | { kind: "error"; message: string };

/** Raise, poll, and hold (or release) a delegated support grant.
 *
 * `held` is owned by the parent (`ProviderConsole`), not this component — the console is
 * what gates the Devices/Monitoring/Backup rail on it, so it has to be the one source of
 * truth both read from. This panel only drives the raise/poll transaction and reports the
 * outcome up via `onGranted`/`onReleased`.
 *
 * The request id lives only in this component's state, not anywhere persisted. Reloading
 * the page mid-poll loses track of it — an accepted, real limitation for this build: there
 * is no "list my own raised requests" route (only the tenant's inbox lists them, and that is
 * correctly scoped away from the provider plane), so recovering it would need new surface
 * this slice does not add. The safe fallback is simply raising again.
 */
export function SupportRequestPanel({
  held,
  onGranted,
  onReleased,
}: {
  held: HeldSupportGrant | null;
  onGranted: (grant: HeldSupportGrant) => void;
  onReleased: () => void;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [scopes, setScopes] = useState<Set<string>>(new Set());
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [tenantsError, setTenantsError] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState("");
  const timer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current != null) window.clearInterval(timer.current);
    };
  }, []);

  // The tenant directory (ADR-0021 scoped) — which tenant to raise this request against.
  // Fetched once: the registry is GitOps-managed, not something that changes mid-session.
  useEffect(() => {
    api.provider
      .listTenants()
      .then((result) => setTenants(result.tenants))
      .catch((err) =>
        setTenantsError(err instanceof ApiError ? err.message : "Could not load the tenant directory"),
      );
  }, []);

  function tenantName(id: string): string {
    return tenants.find((t) => t.tenant_id === id)?.display_name ?? id;
  }

  function toggleScope(scope: string) {
    setScopes((prev) => {
      const next = new Set(prev);
      if (next.has(scope)) next.delete(scope);
      else next.add(scope);
      return next;
    });
  }

  async function raise() {
    setPhase({ kind: "raising" });
    try {
      const result = await api.provider.raiseSupportRequest({
        tenant_id: tenantId,
        requested_scopes: [...scopes],
        justification,
      });
      setPhase({ kind: "pending", requestId: result.request_id, tenantId });
      timer.current = window.setInterval(() => {
        void poll(result.request_id, tenantId);
      }, POLL_INTERVAL_MS);
    } catch (err) {
      setPhase({
        kind: "error",
        message: err instanceof ApiError ? err.message : "Could not raise the request",
      });
    }
  }

  async function poll(requestId: string, forTenantId: string) {
    try {
      const result = await api.provider.pollSupportRequest(requestId, forTenantId);
      if (result.status === "approved") {
        if (timer.current != null) window.clearInterval(timer.current);
        onGranted({ held: true, grant_id: result.grant_id, tenant_id: forTenantId });
      } else if (result.status === "rejected") {
        if (timer.current != null) window.clearInterval(timer.current);
        setPhase({ kind: "rejected" });
      }
      // "pending" — keep polling, nothing to do this tick.
    } catch (err) {
      if (timer.current != null) window.clearInterval(timer.current);
      setPhase({
        kind: "error",
        message: err instanceof ApiError ? err.message : "Could not check the request",
      });
    }
  }

  async function release() {
    setBusy(true);
    try {
      await api.provider.releaseSupportGrant();
      onReleased();
      setPhase({ kind: "idle" });
      setScopes(new Set());
      setJustification("");
    } finally {
      setBusy(false);
    }
  }

  if (held?.held) {
    return (
      <section style={{ display: "grid", gap: 8, maxWidth: 480 }}>
        <p style={{ color: ui.inkSoft }}>
          <strong>{tenantName(held.tenant_id)}</strong> approved a support grant (<code>{held.grant_id}</code>
          ). Devices, Monitoring and Backup are reachable while it lasts — the tenant can end it at any time
          from their own console.
        </p>
        <button onClick={() => void release()} disabled={busy} style={{ justifySelf: "start" }}>
          Release grant
        </button>
      </section>
    );
  }

  if (phase.kind === "pending") {
    return (
      <section style={{ display: "grid", gap: 8, maxWidth: 480 }}>
        <p style={{ color: ui.inkSoft }}>
          Waiting for {tenantName(phase.tenantId)} to approve or reject this request…
        </p>
      </section>
    );
  }

  return (
    <section style={{ display: "grid", gap: 10, maxWidth: 480 }}>
      <p style={{ color: ui.inkSoft }}>
        Raise a support request naming what you need. A tenant admin sees it in their own console and decides
        — nothing here asserts access on its own (ADR-0017).
      </p>
      {phase.kind === "rejected" && <p style={{ color: health.fail }}>The tenant rejected this request.</p>}
      {phase.kind === "error" && <p style={{ color: health.fail }}>{phase.message}</p>}
      {tenantsError && <p style={{ color: health.fail }}>{tenantsError}</p>}
      <label style={{ display: "grid", gap: 4 }}>
        Tenant
        <select value={tenantId} onChange={(e) => setTenantId(e.target.value)}>
          <option value="">— select a tenant —</option>
          {tenants.map((t) => (
            <option key={t.tenant_id} value={t.tenant_id}>
              {t.display_name}
            </option>
          ))}
        </select>
      </label>
      <div style={{ display: "grid", gap: 4 }}>
        {OFFERED_SCOPES.map((scope) => (
          <label key={scope} style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={scopes.has(scope)} onChange={() => toggleScope(scope)} />
            {scope}
          </label>
        ))}
      </div>
      <textarea
        placeholder="justification — ticket, incident, what you are about to do"
        value={justification}
        onChange={(e) => setJustification(e.target.value)}
        rows={3}
      />
      <button
        onClick={() => void raise()}
        disabled={phase.kind === "raising" || !tenantId || scopes.size === 0 || !justification.trim()}
        style={{ justifySelf: "start" }}
      >
        Raise request
      </button>
    </section>
  );
}
