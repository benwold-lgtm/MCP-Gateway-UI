// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The invoke panel. `toolArgs.test.ts` already proves the arguments are built correctly; what
// is untested until here is whether the operator can *see* the two things that make this
// screen safe to use — what is about to be sent, and which side failed when it does.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ToolInvoke } from "../components/ToolInvoke";
import type { Tool } from "../types";

const { invokeTool } = vi.hoisted(() => ({ invokeTool: vi.fn() }));

vi.mock("../api", () => ({
  api: { invokeTool },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

const tool = (over: Partial<Tool> = {}): Tool => ({
  name: "add",
  description: "",
  method: "",
  path: "",
  schema: {
    properties: { a: { type: "integer" }, b: { type: "integer" } },
    required: ["a", "b"],
    type: "object",
  },
  ...over,
});

const OK = {
  jsonrpc: "2.0",
  id: 2,
  result: { content: [{ type: "text", text: "42" }], structuredContent: { result: 42 }, isError: false },
};

function renderPanel(over: Partial<Parameters<typeof ToolInvoke>[0]> = {}) {
  return render(<ToolInvoke hostname="refmcp" tool={tool()} canInvoke {...over} />);
}

describe("ToolInvoke", () => {
  beforeEach(() => {
    invokeTool.mockReset();
    invokeTool.mockResolvedValue(OK);
  });

  it("sends typed arguments and renders the result", async () => {
    renderPanel();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: /^a/ }), "2");
    await user.type(screen.getByRole("textbox", { name: /^b/ }), "40");
    await user.click(screen.getByRole("button", { name: /run add/i }));
    await waitFor(() => expect(invokeTool).toHaveBeenCalledWith("refmcp", "add", { a: 2, b: 40 }));
    expect(await screen.findByText("42")).toBeInTheDocument();
  });

  it("shows what will be sent, after conversion", async () => {
    // The last cheap moment before a write into a customer's live estate. It must show the
    // converted payload — an operator seeing `"2"` where the panel will send `2` learns
    // nothing about what is actually leaving.
    renderPanel();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: /^a/ }), "2");
    await user.type(screen.getByRole("textbox", { name: /^b/ }), "40");
    await user.click(screen.getByText(/what will be sent/i));
    expect(screen.getByText(/"a": 2/)).toBeInTheDocument();
  });

  it("will not run while an argument cannot be built", async () => {
    renderPanel();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: /^a/ }), "12abc");
    await user.type(screen.getByRole("textbox", { name: /^b/ }), "1");
    expect(screen.getByText("Must be a whole number.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run add/i })).toBeDisabled();
    expect(invokeTool).not.toHaveBeenCalled();
  });

  it("refuses to run before a required argument is given", async () => {
    renderPanel();
    expect(screen.getByRole("button", { name: /run add/i })).toBeDisabled();
  });

  it("reports a call refused over HTTP 200 as a failure, not a result", async () => {
    // The trap the transport sets: `req` resolves, so nothing throws. A panel that keyed off
    // the promise settling would render this as success.
    invokeTool.mockResolvedValue({
      jsonrpc: "2.0",
      id: 2,
      error: { code: -32602, message: "Invalid params: a: '2' is not of type 'integer'" },
    });
    renderPanel();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: /^a/ }), "2");
    await user.type(screen.getByRole("textbox", { name: /^b/ }), "40");
    await user.click(screen.getByRole("button", { name: /run add/i }));
    expect(await screen.findByText(/the call was refused \(-32602\)/i)).toBeInTheDocument();
    expect(screen.getByText(/is not of type 'integer'/)).toBeInTheDocument();
  });

  it("names a tool's own error as the tool's, not the call's", async () => {
    invokeTool.mockResolvedValue({
      result: { content: [{ type: "text", text: "device unreachable" }], isError: true },
    });
    renderPanel();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: /^a/ }), "1");
    await user.type(screen.getByRole("textbox", { name: /^b/ }), "1");
    await user.click(screen.getByRole("button", { name: /run add/i }));
    expect(await screen.findByText(/the tool reported an error/i)).toBeInTheDocument();
    expect(screen.queryByText(/the call was refused/i)).not.toBeInTheDocument();
  });

  it("passes an authorization refusal through in the BFF's own words", async () => {
    // A missing elevation, an inactive pod: the upstream sentence names the remedy, and
    // rewriting it into "could not invoke" would cost the operator the useful half.
    const { ApiError } = await import("../api");
    invokeTool.mockRejectedValue(
      new ApiError(403, "This operation needs a live 'provider:invoke' elevation"),
    );
    renderPanel();
    const user = userEvent.setup();
    await user.type(screen.getByRole("textbox", { name: /^a/ }), "1");
    await user.type(screen.getByRole("textbox", { name: /^b/ }), "1");
    await user.click(screen.getByRole("button", { name: /run add/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/provider:invoke/);
  });

  it("offers no control at all without the authority, and says what is missing", async () => {
    renderPanel({ canInvoke: false, reason: "Needs a live elevation." });
    expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument();
    expect(screen.getByText("Needs a live elevation.")).toBeInTheDocument();
  });

  it("runs a no-argument tool without inventing a form", async () => {
    renderPanel({
      tool: tool({
        name: "getstatus",
        schema: { type: "object", properties: {}, required: [], additionalProperties: false },
      }),
    });
    expect(screen.getByText(/takes no arguments/i)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: /run getstatus/i }));
    await waitFor(() => expect(invokeTool).toHaveBeenCalledWith("refmcp", "getstatus", {}));
  });

  it("falls back to a whole-object JSON box when the schema lists no properties", async () => {
    // Not the same as "no arguments": this schema never said what it takes, so a form would
    // be a guess and an empty call would be a silent one.
    renderPanel({ tool: tool({ name: "opaque", schema: { type: "object" } }) });
    const box = screen.getByRole("textbox", { name: /arguments as json/i });
    const user = userEvent.setup();
    await user.clear(box);
    await user.type(box, '{{"q": 1}');
    await user.click(screen.getByRole("button", { name: /run opaque/i }));
    await waitFor(() => expect(invokeTool).toHaveBeenCalledWith("refmcp", "opaque", { q: 1 }));
  });

  it("blocks a run on malformed JSON in the fallback box", async () => {
    renderPanel({ tool: tool({ name: "opaque", schema: { type: "object" } }) });
    const box = screen.getByRole("textbox", { name: /arguments as json/i });
    const user = userEvent.setup();
    await user.clear(box);
    // `[` opens a key descriptor in userEvent's keyboard syntax, so it is escaped as `[[`.
    await user.type(box, "[[not json");
    expect(screen.getByText("Must be valid JSON.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run opaque/i })).toBeDisabled();
  });
});
