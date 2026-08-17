// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Building a tool call from a schema. Every schema below is copied from a tool actually
// registered on the lab gateway (`refmcp`, `tlsprobe`, `prism`), because the two bugs this
// module exists to prevent were both found by calling real tools, not by reading the spec:
//
//   * `{"a": "2"}` against `type: integer` comes back `-32602 Invalid params: a: '2' is not
//     of type 'integer'`. Nothing coerces on the way. A form that sent every input as a
//     string would fail on every numeric tool in the fleet.
//   * A JSON-RPC error arrives over **HTTP 200**, so "did it work" cannot be read from the
//     response code.
import { describe, it, expect } from "vitest";
import { buildArguments, fieldsFor, hasFields, initialValues, readOutcome } from "../toolArgs";

// refmcp/add
const ADD = {
  properties: { a: { title: "A", type: "integer" }, b: { title: "B", type: "integer" } },
  required: ["a", "b"],
  type: "object",
};
// refmcp/delete_all_records — an optional boolean carrying a default
const DELETE_ALL = {
  properties: { confirm: { default: false, title: "Confirm", type: "boolean" } },
  type: "object",
};
// prism/listvms — optional integers with a description
const LIST_VMS = {
  type: "object",
  properties: {
    $limit: {
      type: "integer",
      minimum: 1,
      maximum: 100,
      description: "Maximum number of records to return.",
    },
    $page: { type: "integer", minimum: 0, description: "Zero-based page index." },
  },
  required: [],
  additionalProperties: false,
};
// tlsprobe/getstatus — a real "no arguments" tool
const NO_ARGS = { type: "object", properties: {}, required: [], additionalProperties: false };

const build = (schema: object, values: Record<string, string | boolean>) =>
  buildArguments(fieldsFor(schema), values);

describe("fieldsFor", () => {
  it("reads type, requiredness and description from the schema", () => {
    expect(fieldsFor(LIST_VMS)).toEqual([
      {
        name: "$limit",
        kind: "integer",
        required: false,
        title: undefined,
        description: "Maximum number of records to return.",
        options: undefined,
        initial: "",
      },
      {
        name: "$page",
        kind: "integer",
        required: false,
        title: undefined,
        description: "Zero-based page index.",
        options: undefined,
        initial: "",
      },
    ]);
  });

  it("starts a boolean at its schema default", () => {
    expect(initialValues(fieldsFor(DELETE_ALL))).toEqual({ confirm: false });
  });

  it("renders an enum as a choice whatever its underlying type", () => {
    const f = fieldsFor({ properties: { mode: { type: "string", enum: ["fast", "safe"] } } })[0];
    expect(f.kind).toBe("enum");
    expect(f.options).toEqual(["fast", "safe"]);
  });

  it("falls back to a JSON box for shapes it cannot render as a control", () => {
    // Arrays, nested objects and unions are real schemas an operator may still need to call.
    // Rendering nothing would hide the tool; a JSON box keeps it reachable.
    const fields = fieldsFor({
      properties: { tags: { type: "array" }, spec: { type: "object" }, either: { anyOf: [] } },
    });
    expect(fields.map((f) => f.kind)).toEqual(["json", "json", "json"]);
  });

  it("distinguishes a tool with no arguments from one whose schema lists none", () => {
    // `hasFields` is what stops "takes no arguments" being rendered for a schema that simply
    // never described its properties — those get a whole-object JSON box instead, because
    // guessing empty would send a call with nothing in it.
    expect(hasFields(NO_ARGS)).toBe(true);
    expect(fieldsFor(NO_ARGS)).toEqual([]);
    expect(hasFields({ type: "object" })).toBe(false);
    expect(hasFields(undefined)).toBe(false);
  });
});

describe("buildArguments — types", () => {
  it("sends integers as numbers, not as the strings the input produced", () => {
    // The bug this file exists for. `{"a": "2"}` is refused upstream with -32602.
    const built = build(ADD, { a: "2", b: "40" });
    expect(built).toEqual({ ok: true, args: { a: 2, b: 40 } });
    // `toEqual` compares 2 and "2" as unequal, but state the type outright: this is the
    // single assertion the whole module exists to keep true.
    if (!built.ok) throw new Error("expected the arguments to build");
    expect(typeof built.args.a).toBe("number");
  });

  it("refuses a number-shaped mistake here instead of upstream", () => {
    // "12abc" parses to 12 under parseInt — a value the operator never typed, sent silently.
    expect(build(ADD, { a: "12abc", b: "1" })).toEqual({
      ok: false,
      errors: { a: "Must be a whole number." },
    });
  });

  it("refuses a decimal where the schema says integer", () => {
    expect(build(ADD, { a: "1.5", b: "1" })).toEqual({
      ok: false,
      errors: { a: "Must be a whole number." },
    });
  });

  it("accepts a decimal where the schema says number", () => {
    expect(
      build({ properties: { ratio: { type: "number" } }, required: ["ratio"] }, { ratio: "1.5" }),
    ).toEqual({
      ok: true,
      args: { ratio: 1.5 },
    });
  });

  it("keys every error to its own field", () => {
    // One joined message would make the operator hunt for which of six inputs was wrong.
    expect(build(ADD, { a: "x", b: "y" })).toEqual({
      ok: false,
      errors: { a: "Must be a whole number.", b: "Must be a whole number." },
    });
  });

  it("parses a JSON field into a real value", () => {
    expect(
      build({ properties: { tags: { type: "array" } }, required: ["tags"] }, { tags: '["a","b"]' }),
    ).toEqual({
      ok: true,
      args: { tags: ["a", "b"] },
    });
  });

  it("refuses malformed JSON rather than sending the text", () => {
    expect(build({ properties: { tags: { type: "array" } }, required: ["tags"] }, { tags: "[a" })).toEqual({
      ok: false,
      errors: { tags: "Must be valid JSON." },
    });
  });
});

describe("buildArguments — omitted is not empty", () => {
  it("omits an optional field the operator left alone", () => {
    // Not `{"$limit": ""}`. A schema default applies only to an *absent* key, so sending the
    // empty string silently overrides it.
    expect(build(LIST_VMS, { $limit: "", $page: "" })).toEqual({ ok: true, args: {} });
  });

  it("sends only the optional fields that were filled in", () => {
    expect(build(LIST_VMS, { $limit: "10", $page: "" })).toEqual({ ok: true, args: { $limit: 10 } });
  });

  it("omits an untouched boolean rather than asserting its default", () => {
    // The case that makes this rule earn its keep: were the default `true`, always sending
    // the unchecked box's `false` would invert it without the operator doing anything.
    expect(build(DELETE_ALL, { confirm: false })).toEqual({ ok: true, args: {} });
  });

  it("sends a boolean the operator actually changed", () => {
    expect(build(DELETE_ALL, { confirm: true })).toEqual({ ok: true, args: { confirm: true } });
  });

  it("sends an explicit false against a default of true", () => {
    const schema = { properties: { safe: { default: true, type: "boolean" } } };
    const fields = fieldsFor(schema);
    expect(initialValues(fields)).toEqual({ safe: true });
    expect(buildArguments(fields, { safe: false })).toEqual({ ok: true, args: { safe: false } });
  });

  it("reports a required field left blank instead of omitting it", () => {
    expect(build(ADD, { a: "", b: "2" })).toEqual({ ok: false, errors: { a: "Required." } });
  });

  it("builds an empty object for a tool that takes no arguments", () => {
    expect(build(NO_ARGS, {})).toEqual({ ok: true, args: {} });
  });
});

describe("readOutcome", () => {
  it("reads a successful call", () => {
    // The exact envelope refmcp/add returns.
    expect(
      readOutcome({
        jsonrpc: "2.0",
        id: 2,
        result: {
          content: [{ type: "text", text: "42" }],
          structuredContent: { result: 42 },
          isError: false,
        },
      }),
    ).toEqual({ kind: "ok", text: "42", structured: { result: 42 } });
  });

  it("reads a refused call that arrived over HTTP 200", () => {
    // The whole reason this function exists. The transport reports success; the envelope
    // does not, and only the envelope is telling the truth.
    expect(
      readOutcome({
        jsonrpc: "2.0",
        id: 3,
        error: { code: -32602, message: "Invalid params: a: '2' is not of type 'integer'" },
      }),
    ).toEqual({
      kind: "call-error",
      code: -32602,
      text: "Invalid params: a: '2' is not of type 'integer'",
    });
  });

  it("separates a tool that failed from a call that was refused", () => {
    // Different problems: one says go and look at the device, the other says fix the
    // arguments. A single "it didn't work" costs the operator that distinction.
    const outcome = readOutcome({
      result: { content: [{ type: "text", text: "device unreachable" }], isError: true },
    });
    expect(outcome).toEqual({ kind: "tool-error", text: "device unreachable" });
  });

  it("names content it cannot display rather than rendering blank", () => {
    expect(readOutcome({ result: { content: [{ type: "image" }, { type: "text", text: "ok" }] } })).toEqual({
      kind: "ok",
      text: "[image content]\nok",
      structured: undefined,
    });
  });

  it("treats an unusable envelope as a refusal, not a success", () => {
    expect(readOutcome(null).kind).toBe("call-error");
    expect(readOutcome({ jsonrpc: "2.0", id: 1 }).kind).toBe("call-error");
  });
});
