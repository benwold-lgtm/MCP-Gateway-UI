// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { healthMark, ui, type HealthState } from "../tokens";

/** A device's health, encoded as **shape and colour together** (spec §9).
 *
 * Colour alone is non-negotiably wrong here: device health is exactly the signal a
 * colourblind operator most needs to read at a glance, and a red/green dot pair is the
 * classic failure. The glyphs differ in fill — filled, ringed, hollow — so the three states
 * survive being printed, screenshotted in greyscale, or read by someone who sees no
 * difference between the two colours at all.
 *
 * The label is always rendered, not hidden behind a tooltip. "Unknown (stale)" in particular
 * means something an icon cannot say on its own.
 */
export function HealthDot({ state, title }: { state: HealthState; title?: string }) {
  const mark = healthMark[state];
  return (
    <span
      title={title ?? mark.label}
      style={{ display: "inline-flex", alignItems: "center", gap: 5, whiteSpace: "nowrap" }}
    >
      <span aria-hidden="true" style={{ color: mark.color, fontSize: "0.95em", lineHeight: 1 }}>
        {mark.glyph}
      </span>
      <span style={{ color: state === "online" ? ui.inkSoft : mark.color, fontSize: "0.88em" }}>
        {mark.label}
      </span>
    </span>
  );
}
