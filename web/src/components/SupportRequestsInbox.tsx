// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type {
  ActiveSupportGrant,
  PendingSupportRequest,
  StandingConsent,
  TenantNotification,
} from "../types";
import { health, ui } from "../tokens";

/** The tenant console's own pending-items surface (ADR-0017 §7, slice 8) — the first one:
 * a request a provider operator raised, this deployment's live grants, the standing-consent
 * setting, and the durable notification list. Everything here relays through
 * `require_role("admin")` on the BFF (`routers/support.py`), so this component assumes it is
 * only ever rendered for an admin-equivalent session; it does no role checking of its own.
 */
export function SupportRequestsInbox() {
  return (
    <div style={{ display: "grid", gap: 20, maxWidth: 720 }}>
      <PendingRequests />
      <ActiveGrants />
      <StandingConsentToggle />
      <Notifications />
    </div>
  );
}

function PendingRequests() {
  const [requests, setRequests] = useState<PendingSupportRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.support
      .requests()
      .then(({ requests }) => setRequests(requests))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Could not load pending requests"));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section>
      <h3 style={{ marginBottom: 8 }}>Pending support requests</h3>
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {requests && requests.length === 0 && <p style={{ color: ui.muted }}>Nothing waiting on a decision.</p>}
      {requests && requests.length > 0 && (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
          {requests.map((r) => (
            <PendingRequestRow key={r.request_id} request={r} onDecided={load} />
          ))}
        </ul>
      )}
    </section>
  );
}

function PendingRequestRow({
  request,
  onDecided,
}: {
  request: PendingSupportRequest;
  onDecided: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function decide(action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      if (action === "approve") await api.support.approve(request.request_id);
      else await api.support.reject(request.request_id);
      onDecided();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : `Could not ${action} this request`);
      setBusy(false);
    }
  }

  return (
    <li style={{ borderTop: `1px solid ${ui.rule}`, paddingTop: 8 }}>
      <div>
        <strong>{request.provider_subject}</strong> wants {request.requested_scopes.join(", ")}
      </div>
      <p style={{ margin: "4px 0", color: ui.inkSoft, fontSize: "0.9em" }}>{request.justification}</p>
      {error && <p style={{ margin: "4px 0", color: health.fail, fontSize: "0.85em" }}>{error}</p>}
      <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
        <button onClick={() => void decide("approve")} disabled={busy}>
          Approve
        </button>
        <button onClick={() => void decide("reject")} disabled={busy}>
          Reject
        </button>
      </div>
    </li>
  );
}

function ActiveGrants() {
  const [grants, setGrants] = useState<ActiveSupportGrant[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.support
      .grants()
      .then(({ grants }) => setGrants(grants))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Could not load active grants"));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function revoke(id: string) {
    await api.support.revoke(id);
    load();
  }

  return (
    <section>
      <h3 style={{ marginBottom: 8 }}>Who can reach my stack right now</h3>
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {grants && grants.length === 0 && <p style={{ color: ui.muted }}>No support grants are live.</p>}
      {grants && grants.length > 0 && (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
          {grants.map((g) => (
            <li key={g.id} style={{ borderTop: `1px solid ${ui.rule}`, paddingTop: 8 }}>
              <div>
                <strong>{g.provider_subject}</strong> — {g.scopes.join(", ")}
                {g.self_issued && (
                  <span style={{ color: ui.muted, marginLeft: 8, fontSize: "0.85em" }}>self-issued</span>
                )}
              </div>
              <button onClick={() => void revoke(g.id)} style={{ marginTop: 6 }}>
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function StandingConsentToggle() {
  const [consent, setConsent] = useState<StandingConsent | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.support
      .standingConsent()
      .then(setConsent)
      .catch(() => setConsent(null));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function disable() {
    setBusy(true);
    setError(null);
    try {
      await api.support.disableStandingConsent();
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not disable standing consent");
    } finally {
      setBusy(false);
    }
  }

  if (!consent) return null;

  return (
    <section>
      <h3 style={{ marginBottom: 8 }}>Standing consent</h3>
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {consent.enabled ? (
        <>
          <p style={{ color: ui.inkSoft }}>
            Requests for {consent.scopes.join(", ")} are approved automatically, enabled by{" "}
            {consent.enabled_by}.
          </p>
          <button onClick={() => void disable()} disabled={busy}>
            Disable
          </button>
        </>
      ) : (
        <p style={{ color: ui.muted }}>
          Off — every request needs a human decision. Enabling it is not yet offered from this panel; ask an
          operator to configure it via the gateway API if you need it.
        </p>
      )}
    </section>
  );
}

function Notifications() {
  const [notifications, setNotifications] = useState<TenantNotification[] | null>(null);

  useEffect(() => {
    api
      .notifications()
      .then(({ notifications }) => setNotifications(notifications))
      .catch(() => setNotifications(null));
  }, []);

  if (!notifications || notifications.length === 0) return null;

  return (
    <section>
      <h3 style={{ marginBottom: 8 }}>Notifications</h3>
      <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
        {notifications.map((n) => (
          <li
            key={n.id}
            style={{
              borderLeft: `3px solid ${n.severity === "critical" ? health.fail : ui.rule}`,
              paddingLeft: 8,
            }}
          >
            <p style={{ margin: 0 }}>{n.message}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
