// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";

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
    expect(registerDevice).toHaveBeenCalledWith({
      hostname: "sensor-1",
      base_url: "http://sensor-1.local",
      transport: "sse",
      auth_type: "api_key",
      auth: { api_key: "secret-key", location: "header", name: "X-API-Key" },
    });
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
      transport: "sse",
    });
    // No auth/auth_type in the payload → gateway preserves stored credentials.
    expect(updateDevice.mock.calls[0][1]).not.toHaveProperty("auth");
    expect(updateDevice.mock.calls[0][1]).not.toHaveProperty("auth_type");
    expect(onDone).toHaveBeenCalled();
  });
});
