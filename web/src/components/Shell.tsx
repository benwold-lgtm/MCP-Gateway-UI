// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import type { ReactNode } from "react";
import { ui } from "../tokens";

/** The application shell (spec §9's layout signature).
 *
 * An operations console is *scanned and operated*, not read top to bottom, so the chrome is
 * persistent and the content area is the only thing that scrolls. That is the whole reason
 * this exists: the previous layout was a centred column of stacked cards, which reads as a
 * settings page — everything that mattered scrolled away, including the countdown on a live
 * grant and the health of the fleet being worked on.
 *
 * Three fixed regions, each earning its place:
 *
 *  * **Rail** — where you are and where you can go. Persistent, so navigation is never a
 *    thing you scroll to find.
 *  * **Content** — the only scrolling region.
 *  * **Status strip** — the answers to questions an operator asks continuously rather than
 *    once: whose estate is this, how long have I got, how fresh is what I am reading.
 *    A strip is the right shape for those because they are true of the whole screen, not of
 *    any one panel in it.
 */
export function Shell({
  brand,
  eyebrow,
  rail,
  status,
  identity,
  children,
}: {
  brand: string;
  eyebrow?: string;
  rail: ReactNode;
  status?: ReactNode;
  identity?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div
      style={{
        display: "grid",
        // Rail and strip are fixed; the content column takes what is left. `minmax(0, 1fr)`
        // rather than `1fr` so a wide table scrolls inside the content area instead of
        // stretching the grid and pushing the rail off-screen.
        gridTemplateColumns: "216px minmax(0, 1fr)",
        gridTemplateRows: "1fr auto",
        gridTemplateAreas: '"rail content" "strip strip"',
        height: "100vh",
        overflow: "hidden",
      }}
    >
      <aside
        style={{
          gridArea: "rail",
          borderRight: `1px solid ${ui.rule}`,
          background: ui.surface,
          padding: "14px 12px",
          display: "flex",
          flexDirection: "column",
          gap: 18,
          overflowY: "auto",
        }}
      >
        <div>
          {eyebrow && (
            <p
              style={{
                margin: 0,
                fontSize: "0.63rem",
                letterSpacing: "0.11em",
                color: ui.muted,
              }}
            >
              {eyebrow}
            </p>
          )}
          <h1 style={{ margin: "1px 0 0", fontSize: "1.15rem", fontWeight: 600 }}>{brand}</h1>
        </div>
        <nav style={{ display: "flex", flexDirection: "column", gap: 3 }}>{rail}</nav>
        <div style={{ marginTop: "auto", fontSize: "0.8rem", color: ui.muted }}>{identity}</div>
      </aside>

      <main style={{ gridArea: "content", overflowY: "auto", padding: "18px 22px" }}>{children}</main>

      {status && (
        <footer
          style={{
            gridArea: "strip",
            borderTop: `1px solid ${ui.rule}`,
            background: ui.surface,
            padding: "5px 14px",
            display: "flex",
            alignItems: "center",
            gap: 16,
            flexWrap: "wrap",
            fontSize: "0.8rem",
            color: ui.inkSoft,
            minHeight: 30,
          }}
        >
          {status}
        </footer>
      )}
    </div>
  );
}

/** One rail destination. Disabled entries stay visible rather than disappearing — a console
 *  that hides what you cannot currently reach teaches nothing about why. */
export function RailItem({
  label,
  active,
  disabled,
  hint,
  onClick,
}: {
  label: string;
  active?: boolean;
  disabled?: boolean;
  hint?: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || active}
      title={disabled ? hint : undefined}
      style={{
        textAlign: "left",
        border: "1px solid transparent",
        borderRadius: 4,
        padding: "5px 9px",
        background: active ? ui.actSoft : "transparent",
        color: disabled ? ui.muted : active ? ui.act : ui.ink,
        fontWeight: active ? 600 : 400,
        cursor: disabled ? "default" : active ? "default" : "pointer",
        opacity: disabled ? 0.65 : 1,
      }}
    >
      {label}
      {disabled && hint && (
        <span style={{ display: "block", fontSize: "0.72rem", color: ui.muted, fontWeight: 400 }}>
          {hint}
        </span>
      )}
    </button>
  );
}

/** A labelled reading in the status strip. Label above value, so a row of them scans as a
 *  row of facts rather than a sentence. */
export function StatusItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "baseline", gap: 5 }}>
      <span style={{ fontSize: "0.68rem", letterSpacing: "0.05em", color: ui.muted }}>{label}</span>
      <span>{children}</span>
    </span>
  );
}
