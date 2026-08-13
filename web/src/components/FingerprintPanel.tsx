// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { DeviceFull, Diagnostics } from "../types";

// Endpoint fingerprint (gateway ADR-0015, F-69) — what a device *is*.
//
// The one rule this file exists to enforce: the three dimensions are rendered as three
// separately-labelled groups and are never combined into a single "verified" badge.
// `tls_spki_sha256` is cryptographic; `declared_name`/`declared_version` are whatever the
// upstream chose to say about itself. One badge over both would lend the self-reported
// half a weight it has not earned, and an operator would reasonably read it as identity.
//
// The state chip is therefore about the *pin* (unpinned / pinned / pending approval), not
// about trust. Even "pinned" only means "the same key as last time" — the first
// observation was trust-on-first-use and validated nothing.

export function FingerprintPanel({
  device,
  tls,
  canWrite,
  onApproved,
}: {
  device: DeviceFull;
  tls?: Diagnostics["tls"];
  canWrite: boolean;
  onApproved: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const state = device.fingerprint_state ?? "unpinned";
  const pending = state === "pending_approval";

  async function approve() {
    setBusy(true);
    setError(null);
    try {
      await api.approveFingerprint(device.hostname);
      onApproved();
    } catch (err) {
      // A 409 means the device is no longer pending — someone else approved it, or a
      // re-probe moved the state. Say so rather than leaving a button that looks broken;
      // the refresh then shows what is actually true now.
      setError(err instanceof ApiError ? err.message : "Approval failed");
      if (err instanceof ApiError && err.status === 409) onApproved();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ marginTop: 16 }}>
      <h3 style={{ marginBottom: 2 }}>
        Endpoint fingerprint <StateChip state={state} />
      </h3>
      <p style={{ color: "#666", fontSize: 13, margin: "2px 0 8px" }}>
        Three independent dimensions, kept separate on purpose — they answer different questions and carry
        different weight.
      </p>

      {pending && <PendingApproval device={device} canWrite={canWrite} busy={busy} onApprove={approve} />}
      {error && <p style={{ color: "crimson", fontSize: 13 }}>{error}</p>}

      <Group
        title="Authenticated"
        caption="Cryptographic. The gateway pins the public-key digest (SPKI), not the certificate — a routine renewal reissues against the same key, so it stays quiet until the key itself changes."
      >
        <TlsRows device={device} tls={tls} />
      </Group>

      <Group
        title="Self-reported"
        caption="Sent by the device about itself, so it can be spoofed. Useful as a change signal; never evidence of identity."
      >
        {device.declared_name || device.declared_version ? (
          <>
            <Row label="Name" value={device.declared_name ?? "—"} />
            <Row label="Version" value={device.declared_version ?? "—"} />
          </>
        ) : (
          <Row label="Declared identity" value="— none reported by this device" muted />
        )}
      </Group>

      <Group
        title="Behavioural"
        caption="What the device actually exposes. Bumps whenever a spec change alters the tool set."
      >
        <Row label="Tools revision" value={String(device.tools_revision ?? 0)} />
      </Group>

      <table cellPadding={4} style={{ borderCollapse: "collapse", marginTop: 8 }}>
        <tbody>
          <tr>
            <td style={{ color: "#666", paddingRight: 16, verticalAlign: "top" }}>Policy</td>
            <td style={{ fontSize: 13 }}>{policyText(device.fingerprint_policy)}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

// --- pending approval --------------------------------------------------------

function PendingApproval({
  device,
  canWrite,
  busy,
  onApprove,
}: {
  device: DeviceFull;
  canWrite: boolean;
  busy: boolean;
  onApprove: () => void;
}) {
  return (
    <div
      role="group"
      aria-label="TLS key change pending approval"
      style={{
        border: "1px solid #e0a800",
        background: "#fff8e1",
        borderRadius: 6,
        padding: "8px 12px",
        margin: "8px 0",
      }}
    >
      <b>The TLS key changed</b>
      <p style={{ fontSize: 13, margin: "4px 0" }}>
        A changed key is indistinguishable from a substituted endpoint, which is why this needs a person.
        Approving re-pins the device to the key it is presenting now — it records a decision, it does not
        verify who the endpoint is.
      </p>
      <table cellPadding={4} style={{ borderCollapse: "collapse" }}>
        <tbody>
          <Row label="Pinned key" value={device.tls_spki_sha256 ?? "—"} />
          <Row label="Now presenting" value={device.pending_tls_spki_sha256 ?? "—"} danger />
        </tbody>
      </table>
      {canWrite ? (
        <button onClick={onApprove} disabled={busy} style={{ marginTop: 6 }}>
          {busy ? "Approving…" : "Approve new key"}
        </button>
      ) : (
        <p style={{ fontSize: 13, color: "#666", margin: "6px 0 0" }}>
          Approval needs an admin session (the gateway requires <code>devices:write</code>).
        </p>
      )}
    </div>
  );
}

// --- the authenticated dimension ---------------------------------------------

function TlsRows({ device, tls }: { device: DeviceFull; tls?: Diagnostics["tls"] }) {
  // No pinned key is not automatically a gap. An http:// upstream has no certificate at
  // all, and reporting that as a missing check would be a standing false alarm.
  if (!device.tls_spki_sha256) {
    const plain = device.base_url?.startsWith("http://");
    return (
      <Row
        label="TLS key (SPKI)"
        value={
          plain
            ? "— this device is reached over http://, so there is no key to pin"
            : "— not observed yet; the pin is set on the first successful probe"
        }
        muted
      />
    );
  }
  return (
    <>
      <Row label="TLS key (SPKI)" value={device.tls_spki_sha256} />
      <Row
        label="Pinned"
        value={device.fingerprint_pinned_at ? whenText(device.fingerprint_pinned_at) : "—"}
      />
      <Row label="Certificate" value={device.tls_cert_sha256 ?? "—"} />
      <Row label="Issuer" value={device.tls_issuer ?? "—"} />
      <Row label="Expires" value={device.tls_not_after ?? "—"} />
      {tls && (
        <Row
          label="Chain verification"
          value={
            tls.verify
              ? `on (${tls.source} trust${tls.ca_bundle ? `, ${tls.ca_bundle}` : ""})`
              : `off (${tls.source} trust) — the pin still catches a key change, but nothing checked the certificate was legitimate when it was first pinned`
          }
          danger={!tls.verify}
        />
      )}
    </>
  );
}

// --- presentation ------------------------------------------------------------

function Group({ title, caption, children }: { title: string; caption: string; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ fontWeight: 600, fontSize: 13 }}>{title}</div>
      <div style={{ color: "#777", fontSize: 12, maxWidth: 620 }}>{caption}</div>
      <table cellPadding={4} style={{ borderCollapse: "collapse", marginTop: 2 }}>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function Row({
  label,
  value,
  danger,
  muted,
}: {
  label: string;
  value: string;
  danger?: boolean;
  muted?: boolean;
}) {
  return (
    <tr>
      <td style={{ color: "#666", paddingRight: 16, verticalAlign: "top", whiteSpace: "nowrap" }}>{label}</td>
      <td
        style={{
          color: danger ? "crimson" : muted ? "#888" : "inherit",
          fontFamily: "ui-monospace, monospace",
          fontSize: 12,
          wordBreak: "break-all",
          maxWidth: 620,
        }}
      >
        {value}
      </td>
    </tr>
  );
}

function StateChip({ state }: { state: string }) {
  // Deliberately describes the pin, not trust. "pinned" means "same key as last time" —
  // the baseline itself was trust-on-first-use.
  const look: Record<string, { text: string; bg: string; fg: string; title: string }> = {
    pinned: {
      text: "pinned",
      bg: "#e8f5e9",
      fg: "#2a7",
      title: "The key matches the one recorded on the first successful probe",
    },
    pending_approval: {
      text: "pending approval",
      bg: "#fff8e1",
      fg: "#a67c00",
      title: "The key changed and needs an operator decision",
    },
    unpinned: {
      text: "unpinned",
      bg: "#f4f4f4",
      fg: "#666",
      title: "No key recorded — an http:// upstream has none, and a new device has not been probed yet",
    },
  };
  const l = look[state] ?? { text: state, bg: "#f4f4f4", fg: "#666", title: state };
  return (
    <span
      title={l.title}
      style={{ fontSize: 12, padding: "1px 6px", borderRadius: 10, background: l.bg, color: l.fg }}
    >
      {l.text}
    </span>
  );
}

function policyText(policy?: string | null): string {
  if (policy === "enforce")
    return "enforce — while approval is pending the gateway refuses tool calls and resource reads for this device.";
  if (policy === "warn") return "warn — a changed key is flagged and recorded; calls keep working.";
  // null means "inherit". The gateway resolves the effective value at enforcement time and
  // does not report it, so naming one here would be a guess presented as a fact.
  return "inherited from the fleet setting (security.fingerprint_policy). If that is enforce, tool calls and resource reads are refused while approval is pending.";
}

function whenText(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString();
}
