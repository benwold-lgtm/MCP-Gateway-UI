// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { Enrolment, EnrolmentInvitation, IssuedInvitation } from "../types";
import { health, ui } from "../tokens";

type Handover = { tenant_id: string; public_gateway_url: string };

/** This tenant's relationship with its provider (ADR-0024 §10) — the other half of the
 * handshake the provider console redeems.
 *
 * Sits under the same Support tab as the request inbox because it is the same authority:
 * `support:administer` covers both, which is the grouping the gateway itself chose on the
 * grounds that an admin who can approve a support request but not see who is enrolled would
 * be holding half a control.
 *
 * **The screen §10 depends on.** §10 chose revocation over expiry, on the reasoning that an
 * expiring supplier relationship fails closed at the worst moment. That trade is only safe if
 * the tenant can actually see the relationship and end it — a dormant enrolment is discoverable
 * by looking and by nothing else. So `last_used_at` is not a detail column here; it is the
 * reason the list is rendered at all, and "never used" is stated in words rather than left as
 * an empty cell a reader would skim past.
 */
export function EnrolmentPanel() {
  const [reload, setReload] = useState(0);
  const [info, setInfo] = useState<Handover | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    api.enrolment
      .thisTenant()
      .then(setInfo)
      .catch(() => setFailed(true));
  }, []);

  // A deployment with no `TENANT_ID` or no `PUBLIC_GATEWAY_URL` — a Lite or single-tenant
  // stack with no provider — cannot complete this handshake at all: the provider console
  // requires the code AND both of these, and refuses to submit without them. Issuing an
  // invitation there produces a one-time credential that is spent on a redemption which
  // cannot succeed, and the operator learns why in somebody else's console.
  //
  // Only the ISSUE form is withheld. The lists below stay, unconditionally, because §10
  // chose revocation over expiry: an enrolment that already exists has to remain visible and
  // endable even from a console whose configuration has since been changed or lost. Hiding
  // the whole panel would take away the control while leaving the relationship standing.
  //
  // A FAILED lookup is not treated as "unconfigured". We would be inferring an absence from
  // a transport error, and the cost of guessing wrong is withholding a working control.
  const unknown = !info && !failed;
  // `!info` here is the failed lookup, per the note above: offer the form rather than infer
  // an absence from a transport error.
  const withhold = Boolean(info) && !(info!.tenant_id && info!.public_gateway_url);

  return (
    <div style={{ display: "grid", gap: 20, maxWidth: 720, marginTop: 20 }}>
      {info && <HandoverDetails info={info} />}
      {!unknown &&
        (withhold && info ? (
          <NoProviderHandshake info={info} />
        ) : (
          <IssueInvitation onIssued={() => setReload((n) => n + 1)} />
        ))}
      <OutstandingInvitations reload={reload} />
      <LiveEnrolments />
    </div>
  );
}

/** Why the invitation form is not offered, naming what to set rather than what is wrong.
 *
 * Phrased as a property of the deployment first and a setting second. Most readers of this
 * are running a single-tenant or Lite stack on purpose and have no provider — for them
 * nothing is broken, and an error-shaped message would send them looking for a fault. The
 * settings are named after that, for the reader who does want the relationship.
 */
function NoProviderHandshake({ info }: { info: Handover }) {
  const missing = [
    info.tenant_id ? null : "TENANT_ID",
    info.public_gateway_url ? null : "PUBLIC_GATEWAY_URL",
  ].filter(Boolean) as string[];

  return (
    <section>
      <h3 style={{ marginBottom: 4 }}>Invite a provider</h3>
      <p style={{ margin: "0 0 8px", color: ui.inkSoft, fontSize: "0.9em" }}>
        This deployment is not set up to work with a provider, so there is nothing to invite them to. That is
        the normal state for a stack you administer yourself.
      </p>
      <p style={{ margin: 0, color: ui.muted, fontSize: "0.9em" }}>
        To hand a provider access, set{" "}
        {missing.map((m, i) => (
          <span key={m}>
            {i > 0 ? " and " : ""}
            <code>{m}</code>
          </span>
        ))}{" "}
        on this console and reload. A provider needs both alongside the invitation code, and cannot redeem one
        without them.
      </p>
    </section>
  );
}

// --- what the provider needs from us -------------------------------------------------------

/** This tenant's id and public gateway address, shown beside the invitation form.
 *
 * §10's handshake needs three values and the console used to produce exactly one. The other
 * two were in a ConfigMap, so issuing an invitation left an admin to source the rest from
 * outside the product and read a tenant id off a deployment by hand.
 *
 * Renders a **named absence** rather than a guess when the deployment has no
 * `PUBLIC_GATEWAY_URL`. The BFF knows an in-cluster gateway address, and showing that would
 * be worse than showing nothing: it looks like an answer and fails at redemption, in the
 * provider's console, with an error naming neither this field nor this tenant.
 */
function HandoverDetails({ info }: { info: Handover }) {
  return (
    <section>
      <h3 style={{ marginBottom: 4 }}>What your provider needs</h3>
      <p style={{ margin: "0 0 8px", color: ui.muted, fontSize: "0.9em" }}>
        Send these two alongside the invitation code. Neither is a secret.
      </p>
      <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 12px", margin: 0 }}>
        <dt style={{ color: ui.muted }}>Tenant id</dt>
        <dd style={{ margin: 0 }}>
          {info.tenant_id ? (
            <code>{info.tenant_id}</code>
          ) : (
            <span style={{ color: health.stale }}>
              not configured — set <code>TENANT_ID</code> on this console
            </span>
          )}
        </dd>
        <dt style={{ color: ui.muted }}>Gateway URL</dt>
        <dd style={{ margin: 0 }}>
          {info.public_gateway_url ? (
            <code>{info.public_gateway_url}</code>
          ) : (
            <span style={{ color: health.stale }}>
              not configured — set <code>PUBLIC_GATEWAY_URL</code> to the address your provider can reach
            </span>
          )}
        </dd>
      </dl>
    </section>
  );
}

function when(seconds: number | null | undefined): string {
  if (!seconds) return "";
  return new Date(seconds * 1000).toLocaleString();
}

// --- issuing ------------------------------------------------------------------------------

function IssueInvitation({ onIssued }: { onIssued: () => void }) {
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setIssued(await api.enrolment.createInvitation(label.trim()));
      setLabel("");
      onIssued();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not issue an invitation");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h3 style={{ marginBottom: 4 }}>Invite a provider</h3>
      <p style={{ margin: "0 0 8px", color: ui.muted, fontSize: "0.9em" }}>
        Hand the code to your provider out of band. It can be redeemed once.
      </p>
      <form onSubmit={submit} style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <label>
          Provider{" "}
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Acme MSP"
            aria-label="Provider name"
          />
        </label>
        <button type="submit" disabled={busy || !label.trim()}>
          {busy ? "Issuing…" : "Issue invitation"}
        </button>
      </form>
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {issued && <IssuedCode issued={issued} onDismiss={() => setIssued(null)} />}
    </section>
  );
}

function IssuedCode({ issued, onDismiss }: { issued: IssuedInvitation; onDismiss: () => void }) {
  const expiry = issued.expires_at ? `, expires ${when(issued.expires_at)}` : "";
  const forWhom = `For ${issued.provider_label}${expiry}. If you lose it, issue another.`;

  /* Shown once and never again. There is no route that re-shows an invitation — the gateway
     keeps only its hash — so the warning is not decoration: dismissing this really is the last
     time this value exists anywhere outside the provider's hands. */
  return (
    <div style={{ marginTop: 10, border: `1px solid ${ui.ruleFirm}`, padding: 10 }}>
      <strong>Copy this now — it is not shown again.</strong>
      <p style={{ margin: "6px 0", fontFamily: "monospace", wordBreak: "break-all" }}>{issued.code}</p>
      <p style={{ margin: "6px 0", color: ui.muted, fontSize: "0.9em" }}>{forWhom}</p>
      <button onClick={onDismiss}>Done</button>
    </div>
  );
}

// --- outstanding invitations ----------------------------------------------------------------

function OutstandingInvitations({ reload }: { reload: number }) {
  const [invitations, setInvitations] = useState<EnrolmentInvitation[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.enrolment
      .invitations()
      .then(({ invitations }) => setInvitations(invitations))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Could not load invitations"));
  }, []);

  useEffect(() => {
    load();
  }, [load, reload]);

  return (
    <section>
      <h3 style={{ marginBottom: 8 }}>Outstanding invitations</h3>
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {invitations && invitations.length === 0 && (
        <p style={{ color: ui.muted }}>None waiting to be redeemed.</p>
      )}
      {invitations && invitations.length > 0 && (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
          {invitations.map((i) => (
            <InvitationRow key={i.code_hash} invitation={i} onRevoked={load} />
          ))}
        </ul>
      )}
    </section>
  );
}

function InvitationRow({
  invitation,
  onRevoked,
}: {
  invitation: EnrolmentInvitation;
  onRevoked: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const expiry = invitation.expires_at ? `, expires ${when(invitation.expires_at)}` : "";
  const provenance = `Issued by ${invitation.created_by}${expiry}`;

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      await api.enrolment.revokeInvitation(invitation.code_hash);
      onRevoked();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not withdraw this invitation");
      setBusy(false);
    }
  }

  return (
    <li style={{ borderTop: `1px solid ${ui.rule}`, paddingTop: 8 }}>
      <div>
        <strong>{invitation.provider_label}</strong>
      </div>
      <p style={{ margin: "4px 0", color: ui.inkSoft, fontSize: "0.9em" }}>{provenance}</p>
      {error && <p style={{ margin: "4px 0", color: health.fail, fontSize: "0.85em" }}>{error}</p>}
      <button onClick={revoke} disabled={busy}>
        {busy ? "Withdrawing…" : "Withdraw"}
      </button>
    </li>
  );
}

// --- live relationships ---------------------------------------------------------------------

function LiveEnrolments() {
  const [enrolments, setEnrolments] = useState<Enrolment[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.enrolment
      .enrolments()
      .then(({ enrolments }) => setEnrolments(enrolments))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Could not load enrolments"));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section>
      <h3 style={{ marginBottom: 4 }}>Enrolled providers</h3>
      <p style={{ margin: "0 0 8px", color: ui.muted, fontSize: "0.9em" }}>
        An enrolment does not expire. Ending one is your control over it.
      </p>
      {error && <p style={{ color: health.fail }}>{error}</p>}
      {enrolments && enrolments.length === 0 && <p style={{ color: ui.muted }}>No provider is enrolled.</p>}
      {enrolments && enrolments.length > 0 && (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 10 }}>
          {enrolments.map((e) => (
            <EnrolmentRow key={e.enrolment_id} enrolment={e} onRevoked={load} />
          ))}
        </ul>
      )}
    </section>
  );
}

function EnrolmentRow({ enrolment, onRevoked }: { enrolment: Enrolment; onRevoked: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const who = enrolment.provider_label || enrolment.provider_subject;

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      await api.enrolment.revoke(enrolment.enrolment_id);
      onRevoked();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not end this enrolment");
      setBusy(false);
    }
  }

  /* Stated in words, not left as a blank cell. `last_used_at` is the field §10's whole
     revocation-over-expiry trade rests on, and "never" is its most interesting value — a
     relationship standing open that nobody has used is exactly what an admin is scanning for,
     and it is the one an empty column hides best. */
  const used = enrolment.last_used_at
    ? `Last used ${when(enrolment.last_used_at)}`
    : "Never used since it was approved";
  const usedTone = enrolment.last_used_at ? ui.inkSoft : health.stale;
  const approved = enrolment.approved_at ? ` on ${when(enrolment.approved_at)}` : "";
  const approval = `Approved by ${enrolment.approved_by}${approved}`;

  return (
    <li style={{ borderTop: `1px solid ${ui.rule}`, paddingTop: 8 }}>
      <div>
        <strong>{who}</strong>
      </div>
      <p style={{ margin: "4px 0", color: ui.inkSoft, fontSize: "0.9em" }}>{approval}</p>
      <p style={{ margin: "4px 0", color: usedTone, fontSize: "0.9em" }}>{used}</p>
      {error && <p style={{ margin: "4px 0", color: health.fail, fontSize: "0.85em" }}>{error}</p>}
      {confirming ? (
        <div style={{ display: "flex", gap: 8, marginTop: 6, alignItems: "center" }}>
          <span style={{ fontSize: "0.9em" }}>{`End it? ${who} loses access immediately.`}</span>
          <button onClick={revoke} disabled={busy}>
            {busy ? "Ending…" : "End enrolment"}
          </button>
          <button onClick={() => setConfirming(false)} disabled={busy}>
            Cancel
          </button>
        </div>
      ) : (
        <button onClick={() => setConfirming(true)}>End enrolment</button>
      )}
    </li>
  );
}
