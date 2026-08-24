// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 Ben Wold. All rights reserved.
//
// `credential_state` — a device that works and cannot authenticate (gateway ADR-0018 §3).
//
// **This is not health, and it must never be rendered as health.** A device needing
// reconnection may be perfectly reachable, its pod running, its spec fetching. What it cannot
// do is get a token. Folding it into `deviceHealth` would be the shorter change and the wrong
// one twice over: it would paint a reachable device as unhealthy, and it would bury the one
// thing an operator can actually act on under a dot that means "wait and see".
//
// The condition arises from a restore. A gateway-minted OAuth2 refresh token is excluded from
// every archive, and for `grant_type=refresh_token` that token *was* the credential — so the
// device comes back registered, reachable, correctly fingerprinted, and unable to authenticate
// until a human re-authorizes it out of band. Nothing an archive can carry re-mints a token
// that required consent.
import { ui } from "../tokens";
import { needsReconnect } from "../credentialState";

/** Amber, matching `pending_approval` on the fingerprint panel — the other place this console
 *  says "this works, and a person still has to decide something". Same semantic class, so the
 *  same colour; an operator should not have to learn two vocabularies for one idea. */
const AMBER_BG = "#fff8e1";
const AMBER_FG = "#a67c00";
const AMBER_RULE = "#e0a800";

const TITLE =
  "Restored without its OAuth2 refresh token, which is excluded from every archive. " +
  "The device is registered and may be reachable, but cannot authenticate until it is re-authorized.";

/** Row-level marker for the fleet list. Renders nothing for a healthy credential — the
 *  common case must stay quiet, or the exceptional one stops standing out. */
export function CredentialChip({ state }: { state?: string }) {
  if (!needsReconnect({ credential_state: state })) return null;
  return (
    <span
      title={TITLE}
      style={{
        fontSize: 12,
        padding: "1px 6px",
        borderRadius: 10,
        marginLeft: 6,
        border: `1px solid ${AMBER_RULE}`,
        background: AMBER_BG,
        color: AMBER_FG,
        whiteSpace: "nowrap",
      }}
    >
      needs reconnect
    </span>
  );
}

/** Detail-view banner. Placed above Diagnostics rather than beside them, because it is not a
 *  diagnostic: every reading in that table can be green while this is true. */
export function NeedsReconnectBanner({ device }: { device: { credential_state?: string } }) {
  if (!needsReconnect(device)) return null;
  return (
    <div
      role="group"
      aria-label="Device credential needs reconnecting"
      style={{
        border: `1px solid ${AMBER_RULE}`,
        background: AMBER_BG,
        borderRadius: 6,
        padding: "8px 12px",
        margin: "8px 0",
      }}
    >
      <b>This device needs re-authorizing</b>
      <p style={{ fontSize: 13, margin: "4px 0", color: ui.ink }}>
        It was restored from an archive without its OAuth2 refresh token. Archives never carry one — the
        gateway mints and rotates it, which makes it runtime state rather than something the tenant
        configured, and many providers invalidate the previous token the moment a new one is issued. A refresh
        token exists because somebody consented once, out of band, so nothing an archive could have carried
        would re-mint it.
      </p>
      <p style={{ fontSize: 13, margin: "4px 0", color: ui.inkSoft }}>
        Re-authorize the device with its provider, then save the new refresh token here. Supplying a
        credential is what clears this — editing anything else deliberately leaves it set, so a rate-limit
        change cannot mark a device reconnected that nobody reconnected.
      </p>
    </div>
  );
}
