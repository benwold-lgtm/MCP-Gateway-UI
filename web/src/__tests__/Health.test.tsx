// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { HealthDot } from "../components/Health";
import { deviceHealth, freshness, healthMark, health, priv } from "../tokens";

const NOW = 1_700_000_000;

describe("deviceHealth", () => {
  it("reads a fresh successful check as online", () => {
    expect(deviceHealth({ reachable: true, last_check: NOW - 10 }, 90, NOW)).toBe("online");
  });

  it("reads a fresh failed check as offline", () => {
    // Confirmed unreachable — something asked recently and got no answer.
    expect(deviceHealth({ reachable: false, last_check: NOW - 10 }, 90, NOW)).toBe("offline");
  });

  it("reads an old check as unknown rather than offline", () => {
    // The distinction the three-state model exists for. A stale reading is not evidence the
    // device is down; it is evidence nothing has recently asked. Calling it offline invents
    // a fact and sends someone to investigate a device that may be perfectly healthy.
    expect(deviceHealth({ reachable: true, last_check: NOW - 500 }, 90, NOW)).toBe("stale");
    expect(deviceHealth({ reachable: false, last_check: NOW - 500 }, 90, NOW)).toBe("stale");
  });

  it("treats a device that was never checked as unknown", () => {
    expect(deviceHealth({ reachable: true, last_check: null }, 90, NOW)).toBe("stale");
  });

  it("falls back to the binary when the gateway publishes no threshold", () => {
    // An older gateway sends no `stale_after_seconds`. Inventing a threshold here would make
    // every device unknown; the honest fallback is the flag the device actually carries.
    expect(deviceHealth({ reachable: true, last_check: null }, null, NOW)).toBe("online");
    expect(deviceHealth({ reachable: false, last_check: null }, undefined, NOW)).toBe("offline");
  });

  it("does not call a device stale inside its own poll window", () => {
    // The threshold is three missed polls. A reading exactly at the boundary is still good —
    // otherwise every device flickers to unknown between two healthy checks.
    expect(deviceHealth({ reachable: true, last_check: NOW - 90 }, 90, NOW)).toBe("online");
  });
});

describe("freshness", () => {
  it("says how old the reading is, in the smallest honest unit", () => {
    expect(freshness(NOW - 42, NOW)).toBe("as of 42s ago");
    expect(freshness(NOW - 600, NOW)).toBe("as of 10m ago");
    expect(freshness(NOW - 7200, NOW)).toBe("as of 2h ago");
  });

  it("distinguishes never-checked from checked-long-ago", () => {
    expect(freshness(null, NOW)).toBe("never checked");
  });
});

describe("HealthDot", () => {
  it("encodes state as shape as well as colour", () => {
    // Non-negotiable per the style spec: a red/green dot pair is unreadable for a colourblind
    // operator, and device health is the signal that matters most. The glyphs differ in fill,
    // so the states survive greyscale and colour blindness alike.
    const glyphs = new Set([healthMark.online.glyph, healthMark.offline.glyph, healthMark.stale.glyph]);
    expect(glyphs.size).toBe(3);
  });

  it("always writes the state out, rather than hiding it in a tooltip", () => {
    render(<HealthDot state="stale" />);
    // "Unknown (stale)" means something no icon can say on its own.
    expect(screen.getByText(/unknown \(stale\)/i)).toBeInTheDocument();
  });

  it("keeps the health palette clear of the privilege colour", () => {
    // The two channels must never collide: an operator has to tell a failing device from a
    // live elevation without reading either label.
    const healthColors: string[] = [health.ok, health.fail, health.stale];
    expect(healthColors).not.toContain(priv.base);
    expect(new Set(healthColors).size).toBe(3);
  });
});
