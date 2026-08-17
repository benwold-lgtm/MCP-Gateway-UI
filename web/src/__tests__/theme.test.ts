// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import { ui, priv, health } from "../tokens";

// Read from disk rather than imported: vitest runs with `css: false`, so a CSS import — even
// `?raw` — is stubbed to nothing, and every assertion below would pass vacuously against an
// empty string. A guard that cannot fail is worse than no guard.
const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");

// The palette exists twice by necessity: `tokens.ts` for anything TypeScript reasons about,
// `index.css` for the document itself. Two copies drift — that is precisely how the old amber
// chrome ended up sitting on top of the stale colour. This is the guard that makes the drift
// fail a build instead of shipping as a subtle collision nobody chose.
function cssVar(name: string): string {
  const m = css.match(new RegExp(`--${name}:\\s*([^;]+);`));
  return (m?.[1] ?? "").trim().toLowerCase();
}

describe("the stylesheet and the tokens agree", () => {
  it.each([
    ["canvas", ui.canvas],
    ["surface", ui.surface],
    ["ink", ui.ink],
    ["ink-soft", ui.inkSoft],
    ["muted", ui.muted],
    ["rule", ui.rule],
  ])("--%s matches tokens", (name, expected) => {
    expect(cssVar(name)).toBe(expected.toLowerCase());
  });

  it("paints the page, not just the components", () => {
    // The gap this file was written after: every component was themed while the document
    // stayed browser-default white.
    expect(css).toMatch(/body\s*\{[^}]*background:\s*var\(--canvas\)/s);
    expect(css).toMatch(/body\s*\{[^}]*color:\s*var\(--ink\)/s);
  });

  it("keeps the privilege colour out of the document stylesheet entirely", () => {
    // Indigo means "you are holding elevated authority right now". A base stylesheet cannot
    // know that, so it must never be able to paint anything with it.
    expect(css.toLowerCase()).not.toContain(priv.base.toLowerCase());
    for (const c of [health.ok, health.fail, health.stale]) {
      expect(css.toLowerCase()).not.toContain(c.toLowerCase());
    }
  });

  it("keeps focus visible, since the console is operated rather than read", () => {
    expect(css).toMatch(/:focus-visible/);
  });
});
