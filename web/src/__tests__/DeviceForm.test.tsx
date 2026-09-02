// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// The console's only route to `POST /devices`, so the assertions that matter most here are
// about the SHAPE of the payload rather than the widgets that produce it. Three rules in the
// gateway's `_validate_upstream` are refusals rather than corrections, and each one turns a
// wrong payload into a failed registration:
//
//  * `upstream_transport` on an OpenAPI device is refused on PRESENCE, not on value — even
//    the correct-looking "http" is a 400. The form never sends the key, and a test says so.
//  * `spec_url` alongside `upstream_kind: "mcp"` is refused, and on a PUT an ABSENT `spec_url`
//    preserves the stored one — so switching a device to mcp needs an explicit null.
//  * a malformed `expected_tls_spki_sha256` is refused, and refusing it refuses the whole
//    registration.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// The bodies below are held OUTSIDE this suite, in `contract/console-device-registration.json`,
// and the BFF suite relays the same objects through a double that enforces the gateway's real
// refusals (`bff/tests/test_console_registration_contract.py`). Asserting against a shared
// literal is what makes the two planes one contract rather than two agreeing doubles — read
// from disk rather than imported so the fixture needs no place in the build's module graph.
// Resolved from the working directory rather than from `import.meta.url`: both this suite and
// the BFF's run one level below the repo root (CI sets `working-directory` to `web` and `bff`),
// and jsdom does not guarantee a file: URL for the module.
const CASES = JSON.parse(
  readFileSync(resolve(process.cwd(), "../contract/console-device-registration.json"), "utf8"),
).cases;

const { getDevice, registerDevice, updateDevice } = vi.hoisted(() => ({
  getDevice: vi.fn(),
  registerDevice: vi.fn(),
  updateDevice: vi.fn(),
}));

vi.mock("../api", () => ({
  api: { getDevice, registerDevice, updateDevice },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  },
}));

import { DeviceForm } from "../components/DeviceForm";

describe("DeviceForm", () => {
  beforeEach(() => {
    getDevice.mockReset();
    registerDevice.mockReset();
    updateDevice.mockReset();
  });

  it("creates an api_key-authenticated device with the full payload", async () => {
    registerDevice.mockResolvedValue({});
    const onDone = vi.fn();
    render(<DeviceForm mode="create" onDone={onDone} onCancel={vi.fn()} />);

    await userEvent.type(screen.getByPlaceholderText("my-sensor"), "sensor-1");
    await userEvent.type(screen.getByPlaceholderText("http://device.local"), "http://sensor-1.local");
    // Choose api_key auth → conditional fields appear.
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Auth" }), "api_key");
    await userEvent.type(screen.getByLabelText("API key"), "secret-key");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => expect(registerDevice).toHaveBeenCalledTimes(1));
    expect(registerDevice).toHaveBeenCalledWith(CASES["openapi-with-api-key"].payload);
    expect(onDone).toHaveBeenCalled();
  });

  it("edits a device: pre-fills from the gateway and PUTs without auth (preserve creds)", async () => {
    getDevice.mockResolvedValue({
      hostname: "sensor-1",
      base_url: "http://old.local",
      spec_url: null,
      rate_limit_rps: null,
      auth_type: "api_key",
    });
    updateDevice.mockResolvedValue({});
    const onDone = vi.fn();
    render(<DeviceForm mode="edit" hostname="sensor-1" onDone={onDone} onCancel={vi.fn()} />);

    // Pre-filled base_url from getDevice.
    const baseUrl = await screen.findByDisplayValue("http://old.local");
    await userEvent.clear(baseUrl);
    await userEvent.type(baseUrl, "http://new.local");
    // Auth defaults to "(unchanged)" — leave it.
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(updateDevice).toHaveBeenCalledTimes(1));
    expect(updateDevice).toHaveBeenCalledWith("sensor-1", {
      base_url: "http://new.local",
      upstream_kind: "openapi",
      spec_url: null,
      transport: "sse",
    });
    // No auth/auth_type in the payload → gateway preserves stored credentials.
    expect(updateDevice.mock.calls[0][1]).not.toHaveProperty("auth");
    expect(updateDevice.mock.calls[0][1]).not.toHaveProperty("auth_type");
    expect(onDone).toHaveBeenCalled();
  });
  // --- ADR-0009: registering an MCP server ---------------------------------------------------

  it("registers an MCP server: sends upstream_kind and never sends upstream_transport", async () => {
    registerDevice.mockResolvedValue({});
    render(<DeviceForm mode="create" onDone={vi.fn()} onCancel={vi.fn()} />);

    await userEvent.type(screen.getByPlaceholderText("my-sensor"), "mcp-1");
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Speaks" }), "mcp");
    await userEvent.type(screen.getByLabelText("Base URL"), "http://mcp-1.local/mcp");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => expect(registerDevice).toHaveBeenCalledTimes(1));
    const payload = registerDevice.mock.calls[0][0];
    expect(payload).toEqual(CASES["mcp-server"].payload);
    expect(payload.upstream_kind).toBe("mcp");
    // The whole reason the field is not modelled: the gateway refuses the KEY on an OpenAPI
    // device regardless of its value, and its only legal value on an mcp device is the one
    // the gateway already defaults to. Sending it can only ever lose.
    expect(payload).not.toHaveProperty("upstream_transport");
    expect(payload.spec_url).toBeNull();
  });

  it("hides Spec URL for an MCP server — the gateway refuses the two together", async () => {
    render(<DeviceForm mode="create" onDone={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.getByLabelText("Spec URL")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Speaks" }), "mcp");
    expect(screen.queryByLabelText("Spec URL")).not.toBeInTheDocument();
  });

  it("does not carry a stored spec_url forward when a device is switched to mcp", async () => {
    // The one that only fails against a real gateway: `data.get("spec_url", existing.spec_url)`
    // means an ABSENT key preserves the stored value, so omitting it here would send the old
    // OpenAPI document along with the new kind — a combination the gateway refuses outright.
    getDevice.mockResolvedValue({
      hostname: "sensor-1",
      base_url: "http://old.local",
      spec_url: "http://old.local/openapi.json",
      upstream_kind: "openapi",
      rate_limit_rps: null,
    });
    updateDevice.mockResolvedValue({});
    render(<DeviceForm mode="edit" hostname="sensor-1" onDone={vi.fn()} onCancel={vi.fn()} />);

    await screen.findByDisplayValue("http://old.local/openapi.json");
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Speaks" }), "mcp");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(updateDevice).toHaveBeenCalledTimes(1));
    const payload = updateDevice.mock.calls[0][1];
    expect(payload.upstream_kind).toBe("mcp");
    expect(payload).toHaveProperty("spec_url", null);
  });

  it("pre-fills the kind from the gateway so an edit does not silently convert the device", async () => {
    getDevice.mockResolvedValue({
      hostname: "mcp-1",
      base_url: "http://mcp-1.local/mcp",
      spec_url: null,
      upstream_kind: "mcp",
      rate_limit_rps: null,
    });
    updateDevice.mockResolvedValue({});
    render(<DeviceForm mode="edit" hostname="mcp-1" onDone={vi.fn()} onCancel={vi.fn()} />);

    await screen.findByDisplayValue("http://mcp-1.local/mcp");
    expect(screen.getByRole("combobox", { name: "Speaks" })).toHaveValue("mcp");
    // Defaulting to "openapi" would turn every unrelated edit — a rate-limit change — into a
    // conversion the operator never asked for.
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(updateDevice).toHaveBeenCalledTimes(1));
    expect(updateDevice.mock.calls[0][1].upstream_kind).toBe("mcp");
  });

  // --- ADR-0015 §8: the pre-pin ---------------------------------------------------------------

  it("sends a pre-pinned TLS key digest, lower-cased", async () => {
    registerDevice.mockResolvedValue({});
    render(<DeviceForm mode="create" onDone={vi.fn()} onCancel={vi.fn()} />);

    await userEvent.type(screen.getByPlaceholderText("my-sensor"), "sensor-1");
    await userEvent.type(screen.getByLabelText("Base URL"), "https://sensor-1.local");
    await userEvent.type(screen.getByLabelText("Pin TLS key"), "AB".repeat(32));
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "On key change" }), "enforce");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() => expect(registerDevice).toHaveBeenCalledTimes(1));
    const payload = registerDevice.mock.calls[0][0];
    expect(payload.expected_tls_spki_sha256).toBe("ab".repeat(32));
    expect(payload.fingerprint_policy).toBe("enforce");
  });

  it("refuses a colon-formatted digest before sending, so the device is never created", async () => {
    // The gateway refuses it too, but only AFTER this became a registration attempt. Catching
    // it here is what keeps the corrected retry from colliding with a half-made device.
    render(<DeviceForm mode="create" onDone={vi.fn()} onCancel={vi.fn()} />);

    await userEvent.type(screen.getByPlaceholderText("my-sensor"), "sensor-1");
    await userEvent.type(screen.getByLabelText("Base URL"), "https://sensor-1.local");
    await userEvent.type(screen.getByLabelText("Pin TLS key"), "AB:CD:EF");
    await userEvent.click(screen.getByRole("button", { name: "Register" }));

    expect(await screen.findByText(/64 hex characters/)).toBeInTheDocument();
    expect(registerDevice).not.toHaveBeenCalled();
  });

  it("omits the pin fields entirely on an edit, because the gateway's PUT ignores them", async () => {
    // Not a styling choice. `_apply_update` parses neither key: an edit that offered them
    // would answer 200 and change nothing, which is worse than not offering them at all.
    getDevice.mockResolvedValue({
      hostname: "sensor-1",
      base_url: "http://old.local",
      spec_url: null,
      upstream_kind: "openapi",
      rate_limit_rps: null,
    });
    render(<DeviceForm mode="edit" hostname="sensor-1" onDone={vi.fn()} onCancel={vi.fn()} />);

    await screen.findByDisplayValue("http://old.local");
    expect(screen.queryByLabelText("Pin TLS key")).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "On key change" })).not.toBeInTheDocument();
  });
});
