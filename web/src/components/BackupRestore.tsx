// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useRef, useState } from "react";
import { api, ApiError } from "../api";
import type { OnConflict, RestoreReport } from "../types";
import { health, mono, ui } from "../tokens";

/** Replaying an archive (ADR-0011, ADR-0013 §5b).
 *
 * **Preview first, and the preview has to be of what you are about to apply.** A two-step
 * confirm is theatre unless the thing confirmed is the thing that runs, so the report is
 * bound to a signature of the exact inputs that produced it — archive text, passphrase,
 * conflict mode, dead-letter flag. Change any of them and Apply goes away with a reason. The
 * failure this prevents is the quiet one: preview with `skip`, switch to `overwrite`, apply,
 * and every device is replaced by a plan nobody read.
 *
 * A dry run is a real prediction rather than a guess — the gateway runs the same preflight and
 * the same per-device gates — so the report is worth reading rather than merely displaying.
 * That is also why the outcomes are rendered per device and not just as counts: `skipped`
 * because a hostname already exists and `failed` because current policy would refuse the
 * registration are very different sentences, and only the per-device reason distinguishes them.
 */

/** Everything that changes what a restore would do. Anything absent from this string is
 *  something an operator could alter between previewing and applying without being noticed. */
function signatureOf(inputs: {
  text: string;
  passphrase: string;
  onConflict: OnConflict;
  includeDeadletters: boolean;
}): string {
  return JSON.stringify([inputs.text, inputs.passphrase, inputs.onConflict, inputs.includeDeadletters]);
}

/** `restored_needs_reconnect` → "restored needs reconnect".
 *
 * `String.replace` with a string pattern replaces the FIRST match only. The outcomes were all
 * single-underscore when this was written, so the missing `/g` was invisible until ADR-0018
 * §3 added two-underscore ones and the console started printing "restored needs_reconnect".
 */
function label(outcome: string): string {
  return outcome.replaceAll("_", " ");
}

/** Amber for "needs a human", red for "did not happen" — the distinction the whole feature
 *  rests on. A `*_needs_reconnect` device **restored successfully**; it simply cannot
 *  authenticate yet. Colouring it like `failed` would tell an operator to go looking for a
 *  restore that went wrong, and the same amber is what the fleet list and the fingerprint
 *  panel already use for "this works and a person still has to decide something". */
const AMBER = "#a67c00";

function outcomeColor(outcome: string): string {
  if (outcome === "failed") return health.fail;
  if (outcome.endsWith("needs_reconnect")) return AMBER;
  return ui.inkSoft;
}

export function BackupRestore({ onApplied }: { onApplied?: () => void }) {
  const [text, setText] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [onConflict, setOnConflict] = useState<OnConflict>("skip");
  const [includeDeadletters, setIncludeDeadletters] = useState(false);
  const [report, setReport] = useState<RestoreReport | null>(null);
  const [busy, setBusy] = useState<"preview" | "apply" | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The inputs the current report was produced from. Cleared, never silently reused.
  const previewedRef = useRef<string | null>(null);

  const current = signatureOf({ text, passphrase, onConflict, includeDeadletters });
  const applied = report != null && report.dry_run === false;
  // Only "stale" while a *plan* is on screen. An applied report also fails the signature
  // check — the ref is cleared after a write — and reporting that as "inputs changed" would
  // be false: nothing changed, the plan was spent. Both disable Apply; they say different
  // things, and mutation testing is what showed the second was carrying no weight until it
  // had its own sentence.
  const stale = report != null && !applied && previewedRef.current !== current;

  async function run(dryRun: boolean) {
    let archive: unknown;
    try {
      archive = JSON.parse(text);
    } catch {
      setError("That is not valid JSON. Paste the exported archive, or choose the file.");
      return;
    }
    setBusy(dryRun ? "preview" : "apply");
    setError(null);
    try {
      const result = await api.restore({
        archive,
        dry_run: dryRun,
        on_conflict: onConflict,
        include_deadletters: includeDeadletters,
        ...(passphrase.trim() ? { passphrase: passphrase.trim() } : {}),
      });
      setReport(result);
      // Bound to the inputs that produced it, so editing anything invalidates Apply.
      previewedRef.current = dryRun ? current : null;
      if (!dryRun) onApplied?.();
    } catch (err) {
      // A wrong passphrase, a missing canary and a key mismatch all arrive as 409 with the
      // gateway's own sentence, which names which one. Rewriting it would cost the operator
      // the only diagnostic they get.
      setReport(null);
      previewedRef.current = null;
      setError(err instanceof ApiError ? err.message : "The restore could not be run.");
    } finally {
      setBusy(null);
    }
  }

  function pickFile(file: File | undefined) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setText(String(reader.result ?? ""));
      // A new archive invalidates the previous plan, exactly like an edit does.
      setReport(null);
      previewedRef.current = null;
      setError(null);
    };
    reader.readAsText(file);
  }

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px", marginTop: 16 }}>
      <h3 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>Restore</h3>

      <div style={{ display: "grid", gap: 8, maxWidth: 720 }}>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Archive file</span>
          <input
            type="file"
            accept="application/json,.json"
            onChange={(e) => pickFile(e.target.files?.[0])}
          />
        </label>

        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Archive (JSON)</span>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={5}
            spellCheck={false}
            placeholder="paste the exported archive, or choose the file above"
            style={{ fontFamily: mono, fontSize: 12 }}
            aria-label="Archive JSON"
          />
        </label>

        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Passphrase</span>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="portable archives only"
            autoComplete="off"
          />
        </label>

        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>If a hostname is already registered</span>
          <select value={onConflict} onChange={(e) => setOnConflict(e.target.value as OnConflict)}>
            <option value="skip">Skip it — leave the existing device untouched</option>
            <option value="overwrite">Overwrite it — replace the existing device</option>
            <option value="fail">Fail — report it and restore nothing for that device</option>
          </select>
        </label>

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={includeDeadletters}
            onChange={(e) => setIncludeDeadletters(e.target.checked)}
          />
          <span style={{ color: ui.ink }}>Restore dead-lettered messages too</span>
        </label>

        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button onClick={() => run(true)} disabled={busy != null || !text.trim()}>
            {busy === "preview" ? "Previewing…" : "Preview"}
          </button>
          {/* Enabled only by a preview of *these* inputs. Not styled as the primary action:
              the safe path is the one that should look like the default. */}
          <button onClick={() => run(false)} disabled={busy != null || report == null || stale || applied}>
            {busy === "apply" ? "Restoring…" : "Apply this plan"}
          </button>
          {stale && (
            <span style={{ color: ui.muted, fontSize: 12 }}>
              Inputs changed since the preview — preview again before applying.
            </span>
          )}
          {applied && (
            <span style={{ color: ui.muted, fontSize: 12 }}>
              Applied. Preview again to run another restore.
            </span>
          )}
          {report == null && !error && (
            <span style={{ color: ui.muted, fontSize: 12 }}>Preview first; a restore is never a guess.</span>
          )}
        </div>
      </div>

      {error && (
        <p style={{ color: health.fail, fontSize: 13 }} role="alert">
          {error}
        </p>
      )}

      {report && <Report report={report} stale={stale} />}
    </section>
  );
}

function Report({ report, stale }: { report: RestoreReport; stale: boolean }) {
  const total = report.devices.length;
  return (
    <div style={{ marginTop: 12, opacity: stale ? 0.55 : 1 }}>
      <div style={{ display: "flex", gap: 12, alignItems: "baseline", flexWrap: "wrap" }}>
        <strong style={{ color: ui.ink }}>
          {report.dry_run ? "Planned" : "Applied"} · {report.kind} · conflicts: {report.on_conflict}
        </strong>
        <span style={{ color: ui.muted, fontSize: 13 }}>
          {total} device{total === 1 ? "" : "s"}
          {report.created_at ? ` · archived ${new Date(report.created_at).toLocaleString()}` : ""}
        </span>
      </div>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", margin: "6px 0" }}>
        {Object.entries(report.counts).map(([outcome, n]) => (
          <span
            key={outcome}
            style={{
              fontSize: 12,
              color: outcomeColor(outcome),
              border: `1px solid ${outcomeColor(outcome) === ui.inkSoft ? ui.rule : outcomeColor(outcome)}`,
              borderRadius: 999,
              padding: "1px 8px",
            }}
          >
            {label(outcome)}: {n}
          </span>
        ))}
      </div>

      {/* The FLEET-level credential fault, first because it subsumes the rest: when the store
          itself is unusable the gateway deliberately produces no per-device credential results
          at all (ADR-0018 §7). Showing per-device rows here would invite an operator to go
          checking N references when one mount is wrong. */}
      {report.credential_store_error && (
        <p
          role="status"
          style={{
            color: health.fail,
            fontSize: 13,
            margin: "6px 0",
            border: `1px solid ${health.fail}`,
            borderRadius: 4,
            padding: "6px 10px",
          }}
        >
          <b>Secret store:</b> {report.credential_store_error}
        </p>
      )}

      {/* Lifted out of the per-device list on purpose, the way the gateway lifts it out of the
          report: a pin discarded on 3 of 500 devices is what gets missed during an incident,
          and it is a change in what this stack trusts. */}
      {report.fingerprint_warnings > 0 && (
        <p style={{ color: health.fail, fontSize: 13, margin: "4px 0" }}>
          {report.fingerprint_warnings} device{report.fingerprint_warnings === 1 ? "" : "s"} would have{" "}
          {report.fingerprint_warnings === 1 ? "its" : "their"} endpoint fingerprint changed or left to
          trust-on-first-use. Check the rows below before applying.
        </p>
      )}

      {/* Amber, not red: these devices restore. What they cannot do is authenticate, and only
          a human can change that — so this is the line an operator has to act on AFTER the
          restore succeeds, which is exactly the kind that gets lost in a green report. */}
      {(report.needs_reconnect ?? 0) > 0 && (
        <p style={{ color: AMBER, fontSize: 13, margin: "4px 0" }}>
          {report.needs_reconnect} device{report.needs_reconnect === 1 ? "" : "s"} will need{" "}
          <b>re-authorizing by a person</b>: an OAuth2 refresh token is excluded from every archive, and for{" "}
          {report.needs_reconnect === 1 ? "this device" : "these devices"} that token was the credential.{" "}
          {report.needs_reconnect === 1 ? "It" : "They"} will restore, stay reachable, and be unable to get a
          token until reconnected.
        </p>
      )}

      {(report.credential_warnings ?? 0) > 0 && (
        <p style={{ color: AMBER, fontSize: 13, margin: "4px 0" }}>
          {report.credential_warnings} device{report.credential_warnings === 1 ? "" : "s"} reference a secret
          that does not exist in <b>this stack&apos;s</b> secret store.{" "}
          {report.credential_warnings === 1 ? "It restores" : "They restore"} as configuration; provisioning
          the secret is a separate operation, and the next dispatch picks it up.
        </p>
      )}

      <div style={{ maxHeight: 260, overflowY: "auto", border: `1px solid ${ui.rule}`, borderRadius: 4 }}>
        <table cellPadding={4} style={{ borderCollapse: "collapse", width: "100%", fontSize: 13 }}>
          <tbody>
            {report.devices.map((d) => (
              <tr key={d.hostname} style={{ borderTop: `1px solid ${ui.rule}` }}>
                <td style={{ fontFamily: mono }}>{d.hostname}</td>
                <td style={{ color: outcomeColor(d.outcome) }}>{label(d.outcome)}</td>
                {/* The reason is what separates "already registered" from "current policy
                    would refuse this registration" — two very different skips. */}
                <td style={{ color: ui.muted }}>{d.reason ?? ""}</td>
                {/* One cell rather than a column per warning kind: both are rare, and two
                    mostly-empty columns squeeze the reason text that is read on every row.
                    Labelled so the two stay distinguishable — they call for different actions
                    (approve a pin vs. provision a secret). */}
                <td>
                  {d.fingerprint_warning && (
                    <div style={{ color: health.fail }}>
                      <b>fingerprint:</b> {d.fingerprint_warning}
                    </div>
                  )}
                  {d.credential_warning && (
                    <div style={{ color: AMBER }}>
                      <b>credential:</b> {d.credential_warning}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
