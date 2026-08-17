// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useState } from "react";
import { api, ApiError } from "../api";
import type { ArchiveKind, BackupPrepared } from "../types";
import { formatCountdown, useCountdown } from "../useCountdown";
import { health, mono, priv, ui } from "../tokens";

/** Exporting the registry (ADR-0011, ADR-0013 §5b).
 *
 * **Two steps, and the reason is not a preference.** A native browser download cannot read a
 * response header, and the gateway delivers a minted passphrase in one — so no single request
 * can hand the operator both the file and the secret that opens it. Step one mints and reveals;
 * step two fetches. Between them the BFF holds a blob it cannot open: ciphertext under
 * `MCP_SECRET_KEY` or under the minted passphrase, neither of which it has.
 *
 * The screen's job is to make three otherwise-invisible facts unmissable:
 *
 *  * **The passphrase is shown exactly once.** The gateway mints it per export and keeps no
 *    copy; neither does the BFF. An operator who does not capture it here has an archive
 *    nobody can ever open. So it stays on screen after the download, and the panel refuses to
 *    reset itself while it is still the only copy in existence.
 *  * **A ciphertext archive is a credential dump too.** It is easy to read "encrypted" as
 *    "safe to email". It is encrypted to *this stack's key*, which the provider holds.
 *  * **The prepared file is claimed on first fetch and expires in two minutes.** Both are
 *    deliberate, and both look like bugs if they are not stated.
 */
export function BackupExport() {
  const [kind, setKind] = useState<ArchiveKind>("ciphertext");
  const [passphrase, setPassphrase] = useState("");
  const [includeDeadletters, setIncludeDeadletters] = useState(false);
  const [prepared, setPrepared] = useState<BackupPrepared | null>(null);
  const [claimed, setClaimed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const left = useCountdown(prepared?.expires_at);
  const expired = prepared != null && left === 0;

  async function prepare() {
    setBusy(true);
    setError(null);
    try {
      // The passphrase is sent only when the operator typed one. Omitting the key entirely is
      // what tells a current gateway to mint its own; sending "" would read as a supplied
      // passphrase of zero length and be refused.
      setPrepared(
        await api.prepareBackup({
          kind,
          include_deadletters: includeDeadletters,
          ...(kind === "portable" && passphrase.trim() ? { passphrase: passphrase.trim() } : {}),
        }),
      );
      setClaimed(false);
      setPassphrase("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "The export could not be prepared.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <h3 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>Export</h3>

      <div style={{ display: "grid", gap: 8, maxWidth: 620 }}>
        <fieldset style={{ border: 0, margin: 0, padding: 0, display: "grid", gap: 4 }}>
          <legend style={{ fontSize: "0.85em", color: ui.inkSoft, padding: 0 }}>Archive kind</legend>
          <Choice
            checked={kind === "ciphertext"}
            onSelect={() => setKind("ciphertext")}
            label="Ciphertext"
            note="Credentials stay sealed under this stack's key. Restores here, or into any stack sharing that key."
          />
          <Choice
            checked={kind === "portable"}
            onSelect={() => setKind("portable")}
            label="Portable"
            note="Sealed under a passphrase instead, so it crosses key generations and stacks."
          />
        </fieldset>

        {kind === "portable" && (
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Passphrase (optional)</span>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="leave empty and the gateway will generate one"
              autoComplete="new-password"
              // Explicit, because the Portable option's own explainer contains the word
              // "passphrase" — so a by-label lookup matches that radio too.
              aria-label="Archive passphrase"
            />
            <span style={{ color: ui.muted, fontSize: 12 }}>
              A generated passphrase is shown once, here, and stored nowhere. Older gateways require you to
              supply one.
            </span>
          </label>
        )}

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={includeDeadletters}
            onChange={(e) => setIncludeDeadletters(e.target.checked)}
          />
          <span style={{ color: ui.ink }}>Include dead-lettered messages</span>
        </label>

        {/* Said before the export, not after. "Encrypted" reads as "safe to send", and for
            the party holding the key it is the opposite. */}
        <p style={{ margin: 0, color: ui.muted, fontSize: 13 }}>
          Either kind is a complete copy of every credential in this tenant&rsquo;s registry to anyone holding
          the secret that opens it. Treat the file as the credentials themselves.
        </p>

        <div>
          <button onClick={prepare} disabled={busy}>
            {busy ? "Preparing…" : "Prepare export"}
          </button>
        </div>
      </div>

      {error && (
        <p style={{ color: health.fail, fontSize: 13 }} role="alert">
          {error}
        </p>
      )}

      {prepared && (
        <Prepared
          prepared={prepared}
          left={left}
          expired={expired}
          claimed={claimed}
          onClaim={() => setClaimed(true)}
          onDismiss={() => setPrepared(null)}
        />
      )}
    </section>
  );
}

function Choice({
  checked,
  onSelect,
  label,
  note,
}: {
  checked: boolean;
  onSelect: () => void;
  label: string;
  note: string;
}) {
  return (
    <label style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "0 8px" }}>
      <input type="radio" name="archive-kind" checked={checked} onChange={onSelect} />
      <span style={{ color: ui.ink }}>{label}</span>
      <span />
      <span style={{ color: ui.muted, fontSize: 12 }}>{note}</span>
    </label>
  );
}

/** The prepared archive: the passphrase, the download, and the clock on both. */
function Prepared({
  prepared,
  left,
  expired,
  claimed,
  onClaim,
  onDismiss,
}: {
  prepared: BackupPrepared;
  left: number | null;
  expired: boolean;
  claimed: boolean;
  onClaim: () => void;
  onDismiss: () => void;
}) {
  // Indigo, and one of only two places it appears in the console (ADR-0013 §9 reserves it for
  // privilege). A revealed passphrase is the most privileged thing this screen ever shows.
  return (
    <div
      style={{
        marginTop: 12,
        border: `1px solid ${prepared.passphrase ? priv.base : ui.ruleFirm}`,
        borderRadius: 6,
        padding: "10px 14px",
        background: prepared.passphrase ? priv.soft : ui.surface,
      }}
    >
      {prepared.passphrase && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontWeight: 600, color: priv.ink }}>Copy this passphrase now</div>
          <p style={{ margin: "2px 0 6px", color: priv.ink, fontSize: 13 }}>
            It is not stored anywhere and will not be shown again. Without it this archive can never be opened
            — not by you, not by support, not by the gateway that made it.
          </p>
          <code
            style={{
              display: "block",
              fontFamily: mono,
              fontSize: 13,
              background: ui.surface,
              border: `1px solid ${priv.base}`,
              borderRadius: 4,
              padding: "6px 8px",
              wordBreak: "break-all",
              userSelect: "all",
            }}
          >
            {prepared.passphrase}
          </code>
        </div>
      )}

      {expired ? (
        // 410, not 404: the operator did nothing wrong, so the message says what to do rather
        // than implying a mistyped address.
        <p style={{ margin: 0, color: health.fail, fontSize: 13 }}>
          The prepared file expired before it was downloaded. Prepare the export again.
          {prepared.passphrase && " The passphrase above belongs to that expired archive."}
        </p>
      ) : claimed ? (
        <p style={{ margin: 0, color: ui.inkSoft, fontSize: 13 }}>
          Downloaded. A prepared archive is served once, so preparing again is the way to get another copy.
        </p>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          {/* A real link, not a fetch: the response must become a browser download, and
              `download` keeps the server's filename rather than navigating away. */}
          <a
            href={api.downloadBackupUrl(prepared.download_token)}
            download={prepared.filename}
            onClick={onClaim}
            style={{ color: ui.act, fontWeight: 600 }}
          >
            Download {prepared.filename}
          </a>
          <span style={{ color: left != null && left < 30 ? health.fail : ui.muted, fontSize: 12 }}>
            available for {left != null ? formatCountdown(left) : "…"}
          </span>
        </div>
      )}

      {/* Dismissal is manual and always available *except* while an uncaptured generated
          passphrase is the only copy in existence — clearing that automatically would destroy
          the archive's only key on a stray click. */}
      {(claimed || expired) && (
        <div style={{ marginTop: 8 }}>
          <button onClick={onDismiss}>Done</button>
        </div>
      )}
    </div>
  );
}
