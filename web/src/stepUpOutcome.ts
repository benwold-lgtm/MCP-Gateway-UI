// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import type { StepUpOutcome } from "./types";

/** Reads what the step-up callback redirected back with.
 *
 * Its own module rather than a second export from `ProviderConsole`: a component file that
 * also exports a plain function cannot hot-reload cleanly, and a dev tab that silently stops
 * updating is a debugging trap — it looks exactly like code that did not take effect.
 */
export function readStepUpOutcome(search = window.location.search): StepUpOutcome | null {
  const params = new URLSearchParams(search);
  const status = params.get("elevation");
  if (status === "granted") return { status: "granted" };
  if (status === "denied") return { status: "denied", reason: params.get("reason") ?? "unknown" };
  return null;
}
