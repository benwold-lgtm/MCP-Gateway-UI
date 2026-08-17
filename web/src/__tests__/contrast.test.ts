// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { describe, it, expect } from "vitest";
import { health, priv, ui } from "../tokens";

/** WCAG relative luminance. */
function luminance(hex: string): number {
  const h = hex.replace("#", "");
  const parts = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
  const lin = parts.map((c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)));
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
}

function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

// Measured, not assumed. The first version of HealthDot wrote "Offline" in the failing red
// and "Unknown (stale)" in the stale amber — both below 4.5:1 on this canvas, on exactly the
// screen a colourblind or low-vision operator most needs to read.
describe("contrast against the console canvas", () => {
  it.each([
    ["ink", ui.ink],
    ["inkSoft", ui.inkSoft],
    ["muted", ui.muted],
    ["priv", priv.base],
  ])("%s is readable as body text (AA 4.5:1)", (_name, color) => {
    expect(contrast(color, ui.canvas)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(color, ui.surface)).toBeGreaterThanOrEqual(4.5);
  });

  it.each([
    ["ok", health.ok],
    ["fail", health.fail],
    ["stale", health.stale],
  ])("%s is usable as a non-text mark (AA 3:1)", (_name, color) => {
    // Deliberately the *non-text* threshold: these are glyphs, and the label beside them is
    // rendered in ink. Holding them to 4.5 would mean rewriting the spec's own status palette.
    expect(contrast(color, ui.canvas)).toBeGreaterThanOrEqual(3);
  });

  it("keeps the three status marks distinguishable from each other by luminance too", () => {
    // Colour-blind safety comes from the glyph shapes, but marks that also differ in
    // lightness survive greyscale printing and low-quality screenshots.
    const ls = [health.ok, health.fail, health.stale].map(luminance).sort((a, b) => a - b);
    expect(ls[1] - ls[0]).toBeGreaterThan(0.02);
    expect(ls[2] - ls[1]).toBeGreaterThan(0.02);
  });
});
