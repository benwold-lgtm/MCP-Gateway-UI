// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";

/** Seconds left until `expiresAt` (a server-side epoch), never below zero.
 *
 * The whole point of a §8 grant is that it is *absolute* — it does not extend, and nothing
 * the console does renews it. So this counts down toward a fixed instant rather than
 * decrementing a duration: a browser that slept, throttled its timers or lost the tab
 * resumes at the correct remaining time instead of at wherever it stopped ticking.
 *
 * `null` when nothing is held, so a caller can render "no grant" without inventing a zero.
 */
export function useCountdown(expiresAt: number | null | undefined): number | null {
  const [left, setLeft] = useState<number | null>(() => remaining(expiresAt));

  useEffect(() => {
    setLeft(remaining(expiresAt));
    if (expiresAt == null) return;
    const id = setInterval(() => setLeft(remaining(expiresAt)), 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  return left;
}

function remaining(expiresAt: number | null | undefined): number | null {
  if (expiresAt == null) return null;
  return Math.max(0, Math.round(expiresAt - Date.now() / 1000));
}

/** `m:ss`, or `0:00` once spent. Minutes rather than a bare second count because both §8
 * windows are minutes long (300s and 900s) and "4:58" is read at a glance where "298" is
 * arithmetic. */
export function formatCountdown(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}
