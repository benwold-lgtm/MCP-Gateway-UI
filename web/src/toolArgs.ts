// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
/** Turning a tool's JSON Schema into a form, and the form back into arguments.
 *
 * Kept out of the component because this is the part that can be *wrong* in ways a rendered
 * screenshot cannot show. Two failures drove the design, both measured against real tools on
 * the lab gateway rather than imagined:
 *
 * **1. HTML inputs yield strings, and the upstream does not coerce.** `{"a": "2"}` against a
 * schema declaring `integer` comes back `-32602 Invalid params: a: '2' is not of type
 * 'integer'`. So every value is converted to its declared type before it is sent, and a value
 * that cannot be converted is refused *here* — an operator who mistyped a number should be
 * told which field, not handed a JSON-RPC error code.
 *
 * **2. Blank is not the same as absent.** An optional string left empty must be omitted, not
 * sent as `""`: a schema default only applies to an absent key, so sending the empty string
 * silently overrides it. The rule is one sentence — **a field is sent if it is required, or if
 * the operator changed it.**
 *
 * Two guards implement that, and they are not redundant. Blank text is dropped by the emptiness
 * check; the *unchanged* check is what covers everything with no empty state to fall into — a
 * checkbox whose schema default is `true`, or a field pre-filled from a default. Mutation
 * testing is how that division came out: removing the unchanged check leaves every string case
 * passing and breaks only the boolean, so the two guards must be read as covering different
 * ground rather than as one belt-and-braces pair that could be thinned later.
 *
 * Nothing here validates *values* beyond what is needed to build them (no min/max enforcement,
 * no pattern matching). The upstream owns validation and will say so precisely; duplicating it
 * would produce a second, subtly different opinion that drifts.
 */

/** What the form knows how to render for one property. `json` is the escape hatch: any shape
 *  this module cannot express as a control (nested objects, arrays, unions) becomes a raw JSON
 *  box for that field alone, so one exotic property does not cost the operator the whole form. */
export type FieldKind = "string" | "number" | "integer" | "boolean" | "enum" | "json";

export type Field = {
  name: string;
  kind: FieldKind;
  required: boolean;
  title?: string;
  description?: string;
  /** Present only for `enum`. */
  options?: string[];
  /** The schema's own default, rendered as the control's starting value. */
  initial: string | boolean;
};

type Schema = Record<string, unknown>;

const isObject = (v: unknown): v is Schema => typeof v === "object" && v !== null && !Array.isArray(v);

/** Does this schema describe its arguments property-by-property?
 *
 * A tool whose schema has no `properties` key is not a tool with no arguments — it is a tool
 * whose arguments this module cannot describe, and the two must not render the same. The
 * caller shows a whole-object JSON box for the second, because guessing "takes no arguments"
 * would produce a call that silently sends nothing.
 */
export function hasFields(schema: unknown): boolean {
  return isObject(schema) && isObject(schema.properties);
}

/** The renderable fields, in schema order. */
export function fieldsFor(schema: unknown): Field[] {
  if (!hasFields(schema)) return [];
  const props = (schema as Schema).properties as Schema;
  const required = new Set(
    Array.isArray((schema as Schema).required)
      ? ((schema as Schema).required as unknown[]).filter(isString)
      : [],
  );

  return Object.entries(props).map(([name, raw]) => {
    const spec: Schema = isObject(raw) ? raw : {};
    const kind = kindOf(spec);
    return {
      name,
      kind,
      required: required.has(name),
      title: isString(spec.title) ? spec.title : undefined,
      description: isString(spec.description) ? spec.description : undefined,
      options: kind === "enum" ? (spec.enum as unknown[]).filter(isString) : undefined,
      initial: initialFor(kind, spec.default),
    };
  });
}

function isString(v: unknown): v is string {
  return typeof v === "string";
}

function kindOf(spec: Schema): FieldKind {
  // An enum wins over its declared type: a closed list is always better rendered as a choice
  // than as free text, whatever the underlying primitive is.
  if (Array.isArray(spec.enum) && spec.enum.length > 0 && spec.enum.every(isString)) return "enum";
  switch (spec.type) {
    case "string":
      return "string";
    case "integer":
      return "integer";
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    default:
      // Includes arrays, objects, unions, `$ref`, and a missing `type`. All are real schemas
      // the operator may still need to call, so they get a JSON box rather than being hidden.
      return "json";
  }
}

function initialFor(kind: FieldKind, dflt: unknown): string | boolean {
  if (kind === "boolean") return dflt === true;
  if (dflt === undefined) return "";
  // A default is shown as the control's starting text so the operator can see what will be
  // used — and, because "unchanged" means "omitted", leaving it alone still sends nothing and
  // lets the upstream apply that same default itself.
  return typeof dflt === "string" ? dflt : JSON.stringify(dflt);
}

/** Starting values, keyed by field name. */
export function initialValues(fields: Field[]): Record<string, string | boolean> {
  return Object.fromEntries(fields.map((f) => [f.name, f.initial]));
}

export type BuildResult =
  | { ok: true; args: Record<string, unknown> }
  | { ok: false; errors: Record<string, string> };

/** Build the `arguments` object, or report per-field reasons it cannot be built.
 *
 * Errors are keyed by field so the form can put each message beside the control that caused
 * it. A single joined string would make the operator hunt for which of six inputs was wrong.
 */
export function buildArguments(
  fields: Field[],
  values: Record<string, string | boolean>,
  initial: Record<string, string | boolean> = initialValues(fields),
): BuildResult {
  const args: Record<string, unknown> = {};
  const errors: Record<string, string> = {};

  for (const f of fields) {
    const value = values[f.name];
    const untouched = value === initial[f.name];

    // The rule the whole module turns on. Required fields are always sent — an untouched
    // required field is a missing argument, not an omitted one, and is reported below.
    if (!f.required && untouched) continue;

    if (f.kind === "boolean") {
      args[f.name] = value === true;
      continue;
    }

    const text = typeof value === "string" ? value.trim() : "";
    if (text === "") {
      if (f.required) errors[f.name] = "Required.";
      continue;
    }

    switch (f.kind) {
      case "integer": {
        // Deliberately stricter than `parseInt`, which reads "12abc" as 12 and would send a
        // number the operator never typed.
        if (!/^-?\d+$/.test(text)) {
          errors[f.name] = "Must be a whole number.";
          break;
        }
        args[f.name] = Number(text);
        break;
      }
      case "number": {
        const n = Number(text);
        if (!Number.isFinite(n)) {
          errors[f.name] = "Must be a number.";
          break;
        }
        args[f.name] = n;
        break;
      }
      case "json": {
        try {
          args[f.name] = JSON.parse(text);
        } catch {
          errors[f.name] = "Must be valid JSON.";
        }
        break;
      }
      default:
        // string and enum both send text as-is.
        args[f.name] = text;
    }
  }

  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, args };
}

// --- what came back ----------------------------------------------------------

/** The three outcomes of an invocation, which the transport does *not* distinguish for you.
 *
 * A JSON-RPC error arrives over **HTTP 200**, so a console that checked only the status code
 * would render a refused call as a success. And `result.isError` is a fourth state again: the
 * call reached the tool and the tool reported failure. Whose failure it was changes what the
 * operator does next — fix the arguments, or go look at the device — so the two are never
 * collapsed into one "it didn't work".
 */
export type Outcome =
  | { kind: "ok"; text: string; structured?: unknown }
  | { kind: "tool-error"; text: string }
  | { kind: "call-error"; text: string; code?: number };

export function readOutcome(envelope: unknown): Outcome {
  if (!isObject(envelope)) return { kind: "call-error", text: "The gateway returned no usable response." };

  if (isObject(envelope.error)) {
    const code = typeof envelope.error.code === "number" ? envelope.error.code : undefined;
    return {
      kind: "call-error",
      text: isString(envelope.error.message) ? envelope.error.message : "The call was refused.",
      code,
    };
  }

  const result = isObject(envelope.result) ? envelope.result : null;
  if (!result) return { kind: "call-error", text: "The gateway returned no result." };

  const text = textOf(result.content);
  if (result.isError === true) {
    // The tool's own message is the useful part; falling back to a generic sentence only
    // when it sent none.
    return { kind: "tool-error", text: text || "The tool reported an error without a message." };
  }
  return {
    kind: "ok",
    text,
    structured: result.structuredContent,
  };
}

/** MCP content blocks flattened to text. Non-text blocks (images, resources) are named
 *  rather than dropped, so a result that rendered as blank is distinguishable from one that
 *  carried something this console cannot display. */
function textOf(content: unknown): string {
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => {
      if (!isObject(block)) return "";
      if (isString(block.text)) return block.text;
      return isString(block.type) ? `[${block.type} content]` : "";
    })
    .filter(Boolean)
    .join("\n");
}
