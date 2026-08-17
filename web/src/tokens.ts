// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
/** SyncGate console palette (spec §9).
 *
 * The one rule this file exists to enforce: **two color channels that must never visually
 * collide.** Health answers "what is the state of the world"; privilege answers "what am I
 * currently allowed to do". An operator glancing at a screen has to be able to tell a failing
 * device from a live elevation without reading either label, so the two vocabularies are kept
 * apart here rather than negotiated per component.
 *
 * Colours were literals scattered across the provider components before this. That is how the
 * old amber chrome ended up sitting exactly where the spec puts `stale` — a collision nobody
 * chose, introduced one inline style at a time.
 */

/** State of the world. Never used for authority. */
export const health = {
  ok: "#2F8F5B",
  fail: "#C4453E",
  /** Unknown / stale — metrics too old to trust, *not* "offline".
   *
   *  Still provisional (the spec leaves the hex open, §11), but no longer arbitrary. The
   *  first pick, `#8A7A4E`, sat within 0.011 relative luminance of `ok` — a hair apart in
   *  greyscale, so a printed or screenshotted fleet list showed healthy and unknown as the
   *  same shade. This one clears both `ok` and `fail` by >0.04 and reaches 5.9:1 on canvas,
   *  which is comfortably readable rather than merely a legal mark. */
  stale: "#6E5F35",
} as const;

/** State of privilege. Used for elevation and step-up ONLY (§9) — never for chrome, never
 *  for health, never as a general accent. Its scarcity is the whole point: if indigo appears
 *  anywhere else, it stops meaning "you are holding elevated authority right now". */
export const priv = {
  base: "#5B4B8A",
  soft: "#EEEAF5",
  ink: "#3E3260",
} as const;

/** Structural chrome. Deliberately a third, quiet vocabulary so that neither channel above
 *  has to compete with ordinary UI. */
export const ui = {
  canvas: "#F7F8FA",
  surface: "#FFFFFF",
  ink: "#131B2E",
  inkSoft: "#3C4560",
  muted: "#5D6780",
  rule: "#D8DCE3",
  ruleFirm: "#BFC5D1",
  /** The act-on-tenant channel. Cross-tenant authority is real authority, so it must read as
   *  more than plain chrome — but it is not `priv`, which the spec reserves for step-up.
   *  See the open question in the scope doc. */
  act: "#2F4A7A",
  actSoft: "#E8ECF4",
} as const;

export const mono = '"IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace';
export const sans = '"IBM Plex Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif';

/** Health as shape *and* colour. Non-negotiable per §9: colour alone fails for a colourblind
 *  operator, and device health is exactly where that matters most. */
export const healthMark = {
  online: { glyph: "●", color: health.ok, label: "Online" },
  offline: { glyph: "◍", color: health.fail, label: "Offline" },
  stale: { glyph: "◌", color: health.stale, label: "Unknown (stale)" },
} as const;

export type HealthState = keyof typeof healthMark;

/** Which of the three states a device is in (spec §7).
 *
 * The discriminator is **staleness, not the circuit breaker.** The gateway's `BreakerState`
 * is only readable in embedded mode — in distributed mode the pod runs on a worker — so a
 * fleet list cannot be driven by it. Age of the last successful check works in both modes.
 *
 * `staleAfter` comes from the gateway (`stale_after_seconds`), never from a constant here: a
 * threshold hardcoded in the UI would look like a measurement while being a guess, and would
 * be silently wrong on any deployment that tuned its poll interval.
 *
 * "Unknown" is a real answer, not a fallback. A device whose last check is too old to trust
 * is not offline — nothing has recently asked — and reporting it as offline invents a fact.
 */
export function deviceHealth(
  d: { reachable?: boolean; last_check?: number | null },
  staleAfter: number | null | undefined,
  now: number = Date.now() / 1000,
): HealthState {
  // No threshold published (an older gateway) ⇒ do not invent one. Fall back to the binary
  // the device actually carries rather than showing everything as stale.
  if (staleAfter == null) return d.reachable ? "online" : "offline";
  if (d.last_check == null || now - d.last_check > staleAfter) return "stale";
  return d.reachable ? "online" : "offline";
}

/** "as of 42s ago" — how current the reading is, in the smallest honest unit. */
export function freshness(lastCheck: number | null | undefined, now: number = Date.now() / 1000): string {
  if (lastCheck == null) return "never checked";
  const age = Math.max(0, Math.round(now - lastCheck));
  if (age < 90) return `as of ${age}s ago`;
  if (age < 5400) return `as of ${Math.round(age / 60)}m ago`;
  return `as of ${Math.round(age / 3600)}h ago`;
}
