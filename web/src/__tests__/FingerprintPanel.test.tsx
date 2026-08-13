// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Endpoint fingerprint panel (gateway ADR-0015, F-69).
//
// The assertions that carry weight here are the ones about what the UI must NOT say:
// that the three dimensions never collapse into one trust verdict, that an http://
// device's missing pin reads as a fact rather than a gap, and that an unset policy is
// reported as inherited rather than guessed at. Those are the claims the ADR makes, and
// nothing else in the suite would notice them breaking.
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, afterEach } from "vitest";

// Both the spy and the error class are hoisted — the mock factory runs before ordinary
// top-level declarations, so a class defined outside would not exist yet.
const { approveFingerprint, FakeApiError } = vi.hoisted(() => {
  class FakeApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message);
    }
  }
  return { approveFingerprint: vi.fn(), FakeApiError };
});

vi.mock("../api", () => ({
  api: { approveFingerprint },
  ApiError: FakeApiError,
}));

import { FingerprintPanel } from "../components/FingerprintPanel";
import type { DeviceFull, Diagnostics } from "../types";

const SPKI = "a".repeat(64);
const NEW_SPKI = "b".repeat(64);

const PINNED: DeviceFull = {
  hostname: "sensor-1",
  base_url: "https://sensor-1.local",
  transport: "sse",
  reachable: true,
  pod_active: true,
  upstream_kind: "openapi",
  upstream_transport: "http",
  tools_revision: 3,
  fingerprint_state: "pinned",
  fingerprint_pinned_at: 1717500000.0,
  tls_spki_sha256: SPKI,
  tls_cert_sha256: "c".repeat(64),
  tls_issuer: "CN=Lab CA",
  tls_not_after: "2027-01-01T00:00:00Z",
  declared_name: "sensor-api",
  declared_version: "2.1.0",
  fingerprint_policy: null,
};

const VERIFY_ON: Diagnostics["tls"] = {
  source: "fleet",
  verify: true,
  ca_bundle: "lab-ca.pem",
  client_cert: false,
};

function renderPanel(
  device: Partial<DeviceFull> = {},
  opts: { canWrite?: boolean; tls?: Diagnostics["tls"] } = {},
) {
  const onApproved = vi.fn();
  render(
    <FingerprintPanel
      device={{ ...PINNED, ...device }}
      tls={opts.tls ?? VERIFY_ON}
      canWrite={opts.canWrite ?? true}
      onApproved={onApproved}
    />,
  );
  return onApproved;
}

describe("FingerprintPanel", () => {
  // Reset AFTER each test, not before. With vitest 2.1.9, a `mockReset()` immediately
  // preceding a test whose mock returns a rejected promise makes the runner report a
  // spurious unhandled rejection, even though the component catches it — resetting once
  // the promise has settled avoids that while keeping the same isolation.
  afterEach(() => approveFingerprint.mockReset());

  it("keeps the three dimensions separate and never renders a single trust verdict", () => {
    renderPanel();
    // Three labelled groups, not one badge.
    expect(screen.getByText("Authenticated")).toBeInTheDocument();
    expect(screen.getByText("Self-reported")).toBeInTheDocument();
    expect(screen.getByText("Behavioural")).toBeInTheDocument();
    // The self-reported group says so, in the group itself rather than in a footnote.
    expect(screen.getByText(/can be spoofed/)).toBeInTheDocument();
    expect(screen.getByText(/never evidence of identity/)).toBeInTheDocument();
    // No combined verdict anywhere. "pinned" describes the key, not the device.
    expect(screen.queryByText(/^verified$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^trusted$/i)).not.toBeInTheDocument();
  });

  it("shows the full SPKI digest, not a truncation", () => {
    // An operator's check is comparing this against an independently computed digest,
    // which a 16-character preview cannot support.
    renderPanel();
    expect(screen.getByText(SPKI)).toBeInTheDocument();
  });

  it("reports an http:// device's missing pin as a fact, not a gap", () => {
    renderPanel({
      base_url: "http://plain.local",
      fingerprint_state: "unpinned",
      tls_spki_sha256: null,
      tls_cert_sha256: null,
      tls_issuer: null,
      tls_not_after: null,
      fingerprint_pinned_at: null,
    });
    expect(screen.getByText(/no key to pin/)).toBeInTheDocument();
    // Distinct from "we have not looked yet" — conflating them invents a to-do item.
    expect(screen.queryByText(/not observed yet/)).not.toBeInTheDocument();
  });

  it("distinguishes an https device that has not been probed yet", () => {
    renderPanel({
      base_url: "https://new.local",
      fingerprint_state: "unpinned",
      tls_spki_sha256: null,
      fingerprint_pinned_at: null,
    });
    expect(screen.getByText(/not observed yet/)).toBeInTheDocument();
    expect(screen.queryByText(/no key to pin/)).not.toBeInTheDocument();
  });

  it("says an unset policy is inherited instead of naming one", () => {
    renderPanel({ fingerprint_policy: null });
    expect(screen.getByText(/inherited from the fleet setting/)).toBeInTheDocument();
    // The gateway resolves the effective value at enforcement time and does not report
    // it, so stating "warn" here would be a guess presented as a fact.
    expect(screen.queryByText(/^warn —/)).not.toBeInTheDocument();
  });

  it("spells out the consequence when the device's own policy is enforce", () => {
    renderPanel({ fingerprint_policy: "enforce" });
    expect(screen.getByText(/refuses tool calls and resource reads/)).toBeInTheDocument();
  });

  it("flags that chain verification is off without overstating what that breaks", () => {
    renderPanel({}, { tls: { source: "device", verify: false, ca_bundle: null, client_cert: false } });
    const row = screen.getByText(/the pin still catches a key change/);
    expect(row).toBeInTheDocument();
    expect(row.textContent).toMatch(/nothing checked the certificate was legitimate/);
  });

  describe("pending approval", () => {
    const PENDING: Partial<DeviceFull> = {
      fingerprint_state: "pending_approval",
      pending_tls_spki_sha256: NEW_SPKI,
    };

    it("shows both keys and what approving does and does not mean", () => {
      renderPanel(PENDING);
      expect(screen.getByText("pending approval")).toBeInTheDocument();
      // Scoped to the banner: the pinned key also appears in the Authenticated group,
      // which is correct — it is still the pin until someone approves the new one.
      const banner = screen.getByRole("group", { name: /pending approval/i });
      expect(within(banner).getByText(SPKI)).toBeInTheDocument();
      expect(within(banner).getByText(NEW_SPKI)).toBeInTheDocument();
      expect(within(banner).getByText(/it does not verify who the endpoint is/)).toBeInTheDocument();
    });

    it("approves and refreshes on success", async () => {
      approveFingerprint.mockResolvedValue({ status: "fingerprint_approved" });
      const onApproved = renderPanel(PENDING);
      await userEvent.click(screen.getByRole("button", { name: /Approve new key/ }));
      await waitFor(() => expect(approveFingerprint).toHaveBeenCalledWith("sensor-1"));
      expect(onApproved).toHaveBeenCalled();
    });

    it("offers no approve button to a viewer, and says why", () => {
      renderPanel(PENDING, { canWrite: false });
      expect(screen.queryByRole("button", { name: /Approve new key/ })).not.toBeInTheDocument();
      expect(screen.getByText(/needs an admin session/)).toBeInTheDocument();
    });

    it("surfaces a 409 and refreshes, because the screen was stale", async () => {
      // Someone else approved, or a re-probe moved the state. Reporting success here
      // would tell the operator a trust decision landed when it did not.
      approveFingerprint.mockRejectedValue(new FakeApiError(409, "no fingerprint change awaiting approval"));
      const onApproved = renderPanel(PENDING);
      await userEvent.click(screen.getByRole("button", { name: /Approve new key/ }));
      expect(await screen.findByText(/no fingerprint change awaiting approval/)).toBeInTheDocument();
      expect(onApproved).toHaveBeenCalled();
    });

    it("keeps the panel usable when approval fails for another reason", async () => {
      approveFingerprint.mockRejectedValue(new FakeApiError(502, "gateway unreachable"));
      const onApproved = renderPanel(PENDING);
      await userEvent.click(screen.getByRole("button", { name: /Approve new key/ }));
      expect(await screen.findByText(/gateway unreachable/)).toBeInTheDocument();
      // No refresh: nothing changed, and re-reading would only hide the error.
      expect(onApproved).not.toHaveBeenCalled();
      expect(screen.getByRole("button", { name: /Approve new key/ })).toBeEnabled();
    });
  });

  it("reports a device that declares nothing rather than leaving the group blank", () => {
    renderPanel({ declared_name: null, declared_version: null });
    const group = screen.getByText("Self-reported").parentElement!;
    expect(within(group).getByText(/none reported by this device/)).toBeInTheDocument();
  });
});
