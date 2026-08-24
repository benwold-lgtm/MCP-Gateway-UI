// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 Ben Wold. All rights reserved.
//
// The one rule behind `credential_state` (gateway ADR-0018 §3), kept out of the component
// file so both the list and the detail view read it from the same place — and so a change to
// what "needs a human" means cannot land on one surface and miss the other.

/** Whether this device is waiting on a human for its credential.
 *
 * The `?? "ok"` is load-bearing rather than defensive. `openapi-typescript` renders a schema
 * default as a *required* property, so TypeScript believes `credential_state` is always a
 * string — while a gateway older than ADR-0018 §3 omits the field entirely and it arrives
 * `undefined` at runtime. No type checks that; this function is the only place that has to
 * know. `UpstreamKind` carries the same caveat for the same reason.
 *
 * Matching one named state rather than `!== "ok"` is also deliberate: a state this console has
 * never heard of is not an invitation to invent an alarm for it.
 */
export function needsReconnect(d: { credential_state?: string }): boolean {
  return (d.credential_state ?? "ok") === "needs_reconnect";
}
