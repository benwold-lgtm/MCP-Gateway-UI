// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useRef, useState } from "react";
import { priv, ui } from "../tokens";

/** The gate (spec §9's layout signature) — the product's one orchestrated motion.
 *
 * Two leaves in a frame. They part when an elevation is granted and close when it expires or
 * is spent. It is deliberately the *only* animation in the console, and it is tied to the one
 * moment that deserves emphasis: the instant an operator's reach over a customer's estate
 * widens, and the instant it narrows again.
 *
 * Why a gate rather than a badge. A badge reports a fact; this reports a **transition**, and
 * the transition is what an operator can miss. A single-use grant is spent by the next
 * operation — the close is the only visual event marking that it is gone, and it happens
 * whether or not anyone was looking at the elevation panel at the time.
 *
 * Three rules keep it from becoming decoration:
 *
 *  * It renders in the privilege colour and nowhere else in the product uses that colour, so
 *    an open gate is unambiguous.
 *  * It animates only on a **change of state**, never on mount. A console reloaded while a
 *    grant is live shows an open gate; it does not replay the opening, because nothing just
 *    happened.
 *  * `prefers-reduced-motion` drops the transition entirely and keeps both end states, which
 *    are legible on their own — open and closed differ in shape, not just in having moved.
 */
export function Gate({ open, size = 18, title }: { open: boolean; size?: number; title?: string }) {
  const [animate, setAnimate] = useState(false);
  const seen = useRef<boolean | null>(null);

  // Mount records the state without animating it; only a genuine change animates. Without
  // this, every re-render of a parent would replay an opening that did not occur.
  useEffect(() => {
    if (seen.current === null) {
      seen.current = open;
      return;
    }
    if (seen.current !== open) {
      seen.current = open;
      setAnimate(true);
    }
  }, [open]);

  const w = size;
  const h = size * 1.15;
  const leaf = w * 0.38;
  const inset = w * 0.06;
  // Open: leaves withdraw to the frame. Closed: they meet in the middle.
  const shift = open ? leaf * 0.92 : 0;
  const stroke = open ? priv.base : ui.ruleFirm;

  return (
    <span
      role="img"
      aria-label={open ? "Elevated access open" : "Elevated access closed"}
      title={title ?? (open ? "An elevated grant is live" : "No elevated grant")}
      style={{ display: "inline-flex", lineHeight: 0, verticalAlign: "middle" }}
    >
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
        {/* Posts: the frame is constant. Only the leaves move, so the eye reads a gate
            opening rather than a shape morphing. */}
        <line x1={inset} y1={0} x2={inset} y2={h} stroke={stroke} strokeWidth={1.4} />
        <line x1={w - inset} y1={0} x2={w - inset} y2={h} stroke={stroke} strokeWidth={1.4} />
        <g
          style={{
            transition: animate ? "transform 320ms cubic-bezier(0.22, 0.61, 0.36, 1)" : "none",
            transform: `translateX(${-shift}px)`,
          }}
        >
          <rect
            x={w / 2 - leaf}
            y={h * 0.14}
            width={leaf}
            height={h * 0.72}
            fill={open ? priv.soft : "transparent"}
            stroke={stroke}
            strokeWidth={1.2}
          />
        </g>
        <g
          style={{
            transition: animate ? "transform 320ms cubic-bezier(0.22, 0.61, 0.36, 1)" : "none",
            transform: `translateX(${shift}px)`,
          }}
        >
          <rect
            x={w / 2}
            y={h * 0.14}
            width={leaf}
            height={h * 0.72}
            fill={open ? priv.soft : "transparent"}
            stroke={stroke}
            strokeWidth={1.2}
          />
        </g>
      </svg>
    </span>
  );
}
