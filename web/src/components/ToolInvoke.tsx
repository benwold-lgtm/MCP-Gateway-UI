// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useMemo, useState } from "react";
import { api, ApiError } from "../api";
import type { Tool } from "../types";
import {
  buildArguments,
  fieldsFor,
  hasFields,
  initialValues,
  readOutcome,
  type Field,
  type Outcome,
} from "../toolArgs";
import { health, mono, ui } from "../tokens";

/** Calling one tool on one device (W5).
 *
 * This is the console's only write into a customer's live estate that is not a device record,
 * so two things are rendered that a plain "run" button would leave implicit:
 *
 *  * **Exactly what will be sent.** The arguments are typed, defaulted and omitted according
 *    to rules the operator cannot see (`toolArgs.ts`), and some tools on a real fleet are
 *    destructive. The payload preview is the last point at which a mistake is still cheap.
 *  * **Whose failure it was.** A refused call and a tool that ran and reported an error are
 *    different problems — fix the arguments, or go look at the device — and the transport
 *    hands both back over HTTP 200. Collapsing them into "it didn't work" costs the operator
 *    the one thing they needed to know.
 *
 * Gating is the caller's job (`canInvoke`): a tenant admin holds `tools:call` as an ordinary
 * scope. A provider operator currently has no path to this at all (ADR-0017 slice 6 removed
 * the act-on-tenant/elevated-grant mechanism that used to gate provider tool invocation;
 * its replacement is slice 7/8). Neither is decided here — the BFF refuses, then the gateway
 * refuses again on the token it is handed.
 */
export function ToolInvoke({
  hostname,
  tool,
  canInvoke,
  reason,
}: {
  hostname: string;
  tool: Tool;
  canInvoke: boolean;
  /** Why invocation is unavailable, shown in place of the form. An operator who can see the
   *  tool but not run it should learn what would change that. */
  reason?: string;
}) {
  const fields = useMemo(() => fieldsFor(tool.schema), [tool.schema]);
  const structured = hasFields(tool.schema);
  const initial = useMemo(() => initialValues(fields), [fields]);

  const [values, setValues] = useState<Record<string, string | boolean>>(initial);
  // Only used when the schema does not describe its properties — then there is nothing to
  // build a form from, and a raw object is the honest fallback.
  const [rawJson, setRawJson] = useState("{}");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  const built = structured ? buildArguments(fields, values, initial) : parseRaw(rawJson);
  const errors = built.ok ? {} : built.errors;

  async function run() {
    if (!built.ok) return;
    setBusy(true);
    setFailed(null);
    setOutcome(null);
    try {
      setOutcome(readOutcome(await api.invokeTool(hostname, tool.name, built.args)));
    } catch (err) {
      // The BFF's own refusals land here: no elevation (403), no active pod (409). Its
      // message names the reason and is more useful than anything phrased locally.
      setFailed(err instanceof ApiError ? err.message : "The call could not be sent.");
    } finally {
      setBusy(false);
    }
  }

  if (!canInvoke) {
    return (
      <p style={{ color: ui.muted, fontSize: 13, margin: "8px 0 0" }}>
        {reason ?? "You cannot invoke tools on this device."}
      </p>
    );
  }

  return (
    <div style={{ marginTop: 8, display: "grid", gap: 8 }}>
      {structured && fields.length === 0 && (
        <p style={{ color: ui.muted, fontSize: 13, margin: 0 }}>This tool takes no arguments.</p>
      )}

      {structured &&
        fields.map((f) => (
          <FieldControl
            key={f.name}
            field={f}
            value={values[f.name]}
            error={errors[f.name]}
            onChange={(v) => setValues((prev) => ({ ...prev, [f.name]: v }))}
          />
        ))}

      {!structured && (
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>
            Arguments (JSON) — this tool&rsquo;s schema does not list its properties
          </span>
          <textarea
            value={rawJson}
            onChange={(e) => setRawJson(e.target.value)}
            rows={4}
            spellCheck={false}
            style={{ fontFamily: mono, fontSize: 12 }}
            aria-label="Arguments as JSON"
          />
          {!built.ok && built.errors._ && (
            <span style={{ color: health.fail, fontSize: 12 }}>{built.errors._}</span>
          )}
        </label>
      )}

      {/* The last cheap moment. Shown after conversion, so an operator sees `42` where they
          typed "42" — and sees an optional field they left alone simply not appear. */}
      {built.ok && (
        <details>
          <summary style={{ cursor: "pointer", fontSize: 12, color: ui.inkSoft }}>What will be sent</summary>
          <pre
            style={{
              background: ui.surface,
              border: `1px solid ${ui.rule}`,
              padding: 8,
              overflowX: "auto",
              fontSize: 12,
              fontFamily: mono,
              margin: "4px 0 0",
            }}
          >
            {JSON.stringify(built.args, null, 2)}
          </pre>
        </details>
      )}

      <div>
        <button onClick={run} disabled={busy || !built.ok}>
          {busy ? "Running…" : `Run ${tool.name}`}
        </button>
      </div>

      {failed && (
        <p style={{ color: health.fail, margin: 0, fontSize: 13 }} role="alert">
          {failed}
        </p>
      )}
      {outcome && <Result outcome={outcome} />}
    </div>
  );
}

/** Anything that is not a property-listing schema gets one JSON box for the whole object.
 *  Errors are keyed `_` so the form's per-field lookup keeps working unchanged. */
function parseRaw(text: string): ReturnType<typeof buildArguments> {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: true, args: {} };
  try {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
      return { ok: false, errors: { _: "Arguments must be a JSON object." } };
    return { ok: true, args: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, errors: { _: "Must be valid JSON." } };
  }
}

function FieldControl({
  field,
  value,
  error,
  onChange,
}: {
  field: Field;
  value: string | boolean;
  error?: string;
  onChange: (v: string | boolean) => void;
}) {
  const label = (
    <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>
      <code style={{ fontFamily: mono }}>{field.name}</code>
      {field.required && <span style={{ color: health.fail }}> *</span>}
      <span style={{ color: ui.muted }}> · {field.kind}</span>
    </span>
  );

  // A checkbox carries its own label, so it is laid out inline rather than stacked.
  if (field.kind === "boolean") {
    return (
      <div style={{ display: "grid", gap: 2 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} />
          {label}
        </label>
        <Hint field={field} error={error} />
      </div>
    );
  }

  return (
    <label style={{ display: "grid", gap: 2 }}>
      {label}
      {field.kind === "enum" ? (
        <select value={String(value)} onChange={(e) => onChange(e.target.value)}>
          {/* An optional enum needs a way back to "unset", or the first option becomes a
              value the operator never chose. */}
          {!field.required && <option value="">(not set)</option>}
          {field.options?.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      ) : field.kind === "json" ? (
        <textarea
          value={String(value)}
          onChange={(e) => onChange(e.target.value)}
          rows={3}
          spellCheck={false}
          style={{ fontFamily: mono, fontSize: 12 }}
        />
      ) : (
        <input
          value={String(value)}
          onChange={(e) => onChange(e.target.value)}
          // Deliberately a text input even for numbers: `<input type="number">` reports an
          // empty string for an unparseable entry, which would turn "1e" into "left blank"
          // and silently omit an argument the operator meant to send.
          inputMode={field.kind === "integer" || field.kind === "number" ? "decimal" : undefined}
        />
      )}
      <Hint field={field} error={error} />
    </label>
  );
}

function Hint({ field, error }: { field: Field; error?: string }) {
  if (error) return <span style={{ color: health.fail, fontSize: 12 }}>{error}</span>;
  if (field.description) return <span style={{ color: ui.muted, fontSize: 12 }}>{field.description}</span>;
  return null;
}

/** The three outcomes, kept visibly apart. */
function Result({ outcome }: { outcome: Outcome }) {
  const failure = outcome.kind !== "ok";
  return (
    <div
      role="status"
      style={{
        border: `1px solid ${failure ? health.fail : ui.rule}`,
        borderRadius: 4,
        padding: "6px 10px",
        background: ui.surface,
      }}
    >
      <div style={{ fontSize: 12, color: failure ? health.fail : ui.inkSoft, marginBottom: 4 }}>
        {outcome.kind === "ok" && "Result"}
        {/* Named separately on purpose: one says fix your arguments, the other says go look
            at the device. */}
        {outcome.kind === "tool-error" && "The tool reported an error"}
        {outcome.kind === "call-error" &&
          `The call was refused${outcome.code != null ? ` (${outcome.code})` : ""}`}
      </div>
      <pre
        style={{
          margin: 0,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          fontFamily: mono,
          fontSize: 12,
          color: ui.ink,
        }}
      >
        {outcome.text || "(no content)"}
      </pre>
      {outcome.kind === "ok" && outcome.structured !== undefined && (
        <details style={{ marginTop: 4 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, color: ui.inkSoft }}>Structured content</summary>
          <pre style={{ margin: "4px 0 0", overflowX: "auto", fontFamily: mono, fontSize: 12 }}>
            {JSON.stringify(outcome.structured, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}
