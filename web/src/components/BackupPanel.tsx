// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { BackupExport } from "./BackupExport";
import { BackupRestore } from "./BackupRestore";
import { ui } from "../tokens";

/** Export and restore of the device registry (ADR-0011).
 *
 * **Rendered on both consoles, because the routes serve both.** `routers/api.py` is mounted
 * on the tenant and provider planes alike, so the capability was always reachable from a
 * tenant session — it simply had no screen, which made "a tenant cannot back up their own
 * stack" look like a boundary while `curl` said otherwise. An unrendered route is not a
 * boundary; the guards below are.
 *
 * What actually gates this, in order of who enforces it:
 *
 *  * **Never a local password session.** All four backup routes carry
 *    `deny_password_session`. A password session proxies with the stack's own admin token,
 *    which holds every `backup:*` scope — so break-glass would export every device
 *    credential in the tenant under a shared secret that has no owner and no expiry. The
 *    refusal is verified on export *and* restore separately: a guard on one is not a guard
 *    on the other.
 *  * **The gateway, on every relayed call.** For an OIDC session `require_role` passes
 *    through by design — the gateway is the authorization point, and `backup:read` /
 *    `backup:write` are what it checks.
 *  * **This component's caller**, which decides whether to offer the screen at all. That is
 *    a courtesy to the operator, not a control: hiding a button denies nothing.
 */
export function BackupPanel() {
  return (
    <section style={{ display: "grid", gap: 4, maxWidth: 760 }}>
      <h2 style={{ margin: 0, fontSize: "1.15em", color: ui.ink }}>Backup and restore</h2>
      <BackupExport />
      <BackupRestore />
    </section>
  );
}
