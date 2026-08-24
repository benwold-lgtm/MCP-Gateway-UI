// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// `credential_state` — gateway ADR-0018 §3.
//
// The property worth the most defending is the one a shorter implementation would get wrong:
// **this is not health.** A device restored without its refresh token can be entirely
// reachable, its pod running, its last check seconds old. Folding the condition into
// `deviceHealth` would paint that device offline and hide the only thing an operator can do
// about it. So the tests below assert the two signals stay independent, in both directions,
// rather than merely that a chip appears.
//
// The second is the runtime/type mismatch. `openapi-typescript` renders a schema default as a
// *required* property, so TypeScript believes `credential_state` is always a string — while a
// gateway older than §3 omits it entirely and it arrives `undefined`. No type checks that, so
// the absent case is tested explicitly on every surface.
import { render, screen, within } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

vi.mock("../api", () => ({
  api: { deleteDevice: vi.fn() },
  ApiError: class ApiError extends Error {},
}));

import { DeviceList } from "../components/DeviceList";
import { CredentialChip, NeedsReconnectBanner } from "../components/CredentialState";
import { needsReconnect } from "../credentialState";
import type { Overview } from "../types";

const OVERVIEW = {
  mode: "distributed",
  counts: { total: 3, active_pods: 3, reachable: 3, unreachable: 0 },
  stale_after_seconds: 600,
  devices: [
    // Restored from an archive and reachable — the combination that makes the point.
    {
      hostname: "rotator",
      base_url: "https://rotator.local",
      transport: "sse",
      reachable: true,
      pod_active: true,
      last_check: Date.now() / 1000,
      upstream_kind: "openapi",
      credential_state: "needs_reconnect",
    },
    {
      hostname: "healthy",
      base_url: "https://healthy.local",
      transport: "sse",
      reachable: true,
      pod_active: true,
      last_check: Date.now() / 1000,
      upstream_kind: "openapi",
      credential_state: "ok",
    },
    // Field absent entirely: an older gateway. Must read as "ok", not as unknown-so-warn.
    {
      hostname: "legacy",
      base_url: "https://legacy.local",
      transport: "sse",
      reachable: true,
      pod_active: true,
      last_check: Date.now() / 1000,
      upstream_kind: "openapi",
    },
  ],
} as unknown as Overview;

function list(overview: Overview = OVERVIEW) {
  render(
    <DeviceList
      overview={overview}
      canWrite={false}
      onChanged={vi.fn()}
      onSelect={vi.fn()}
      onEdit={vi.fn()}
    />,
  );
}

function rowFor(hostname: string) {
  // Not `getByRole("cell", {name})` — the chip joins the hostname cell's accessible name, so
  // an exact-name lookup stops finding precisely the rows this file cares about.
  return screen.getByRole("link", { name: hostname }).closest("tr")!;
}

// ── The rule itself ──────────────────────────────────────────────────────────────────────

describe("needsReconnect", () => {
  it("is true only for the one state that means it", () => {
    expect(needsReconnect({ credential_state: "needs_reconnect" })).toBe(true);
    expect(needsReconnect({ credential_state: "ok" })).toBe(false);
  });

  it("reads an absent field as ok, because an older gateway omits it", () => {
    expect(needsReconnect({})).toBe(false);
    expect(needsReconnect({ credential_state: undefined })).toBe(false);
  });

  it("does not treat an unrecognised future state as needing a human", () => {
    // A state this console has never heard of is not an invitation to invent an alarm for it.
    expect(needsReconnect({ credential_state: "something_new" })).toBe(false);
  });
});

// ── The fleet list ───────────────────────────────────────────────────────────────────────

describe("DeviceList credential state", () => {
  it("marks only the device that needs a human", () => {
    list();
    expect(within(rowFor("rotator")).getByText("needs reconnect")).toBeInTheDocument();
    expect(within(rowFor("healthy")).queryByText("needs reconnect")).toBeNull();
    expect(within(rowFor("legacy")).queryByText("needs reconnect")).toBeNull();
  });

  it("does NOT change how the device's health reads", () => {
    // The load-bearing assertion. This device is reachable and freshly checked; the credential
    // condition is orthogonal, and a console that dimmed the dot would be answering an
    // authorization question with a health signal.
    list();
    const row = within(rowFor("rotator"));
    expect(row.getByText("Online")).toBeInTheDocument();
    expect(row.queryByText("Offline")).toBeNull();
    expect(row.queryByText("Unknown (stale)")).toBeNull();
  });

  it("counts them beside the fleet totals, so the list is worth scanning", () => {
    list();
    expect(screen.getByText("1 need reconnecting")).toBeInTheDocument();
  });

  it("says nothing at all when no device needs one", () => {
    // The common case has to stay quiet, or the exceptional one stops standing out.
    const clean = {
      ...OVERVIEW,
      devices: OVERVIEW.devices.filter((d) => (d as { hostname: string }).hostname !== "rotator"),
    } as unknown as Overview;
    list(clean);
    expect(screen.queryByText(/need reconnecting/)).toBeNull();
    expect(screen.queryByText("needs reconnect")).toBeNull();
  });
});

// ── The pieces in isolation ──────────────────────────────────────────────────────────────

describe("CredentialChip", () => {
  it("renders nothing for a healthy or absent state", () => {
    const { container, rerender } = render(<CredentialChip state="ok" />);
    expect(container).toBeEmptyDOMElement();
    rerender(<CredentialChip state={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("carries its meaning in words, not colour alone", () => {
    // Spec §9: colour alone fails a colourblind operator, and this marker is exactly the kind
    // of thing that gets shipped as a bare amber dot.
    render(<CredentialChip state="needs_reconnect" />);
    expect(screen.getByText("needs reconnect")).toBeInTheDocument();
  });
});

describe("NeedsReconnectBanner", () => {
  it("explains what happened and what the operator must do", () => {
    render(<NeedsReconnectBanner device={{ credential_state: "needs_reconnect" }} />);
    expect(screen.getByRole("group", { name: /needs reconnecting/i })).toBeInTheDocument();
    expect(screen.getByText(/Re-authorize the device with its provider/)).toBeInTheDocument();
    // The non-obvious half: editing something else will not clear it.
    expect(screen.getByText(/editing anything else deliberately leaves it set/)).toBeInTheDocument();
  });

  it("is absent for a device whose credential is fine", () => {
    const { container } = render(<NeedsReconnectBanner device={{ credential_state: "ok" }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("is absent for an older gateway that omits the field", () => {
    const { container } = render(<NeedsReconnectBanner device={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});
