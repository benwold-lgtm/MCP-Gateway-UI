// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 Ben Wold. All rights reserved.
//
// Contract drift guard: compares the committed gateway OpenAPI snapshot
// (web/gateway.openapi.json) against a live/reference gateway spec, so the UI's
// vendored contract can't silently rot out of sync with the gateway (the exact
// failure that left the BFF calling pre-/v1 paths).
//
// Source of the reference spec (first one set wins):
//   GATEWAY_OPENAPI_URL   e.g. http://localhost:8000/openapi.json   (fetched)
//   GATEWAY_OPENAPI_FILE  path to an openapi.json on disk
// If neither is set, the check SKIPS (exit 0) — so ordinary CI without a gateway
// passes, while an integration job or a local dev run can enforce it by setting one.
//
// Usage:  node scripts/check-spec-drift.mjs   (or: npm run check:spec)
// Refresh the snapshot when drift is intentional:
//   curl -s http://localhost:8000/openapi.json | python -m json.tool > gateway.openapi.json
//   npm run gen:types

import { readFile } from "node:fs/promises";

const SNAPSHOT = new URL("../gateway.openapi.json", import.meta.url);

async function loadReference() {
  const url = process.env.GATEWAY_OPENAPI_URL;
  const file = process.env.GATEWAY_OPENAPI_FILE;
  if (url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`fetch ${url} → HTTP ${resp.status}`);
    return { spec: await resp.json(), source: url };
  }
  if (file) {
    return { spec: JSON.parse(await readFile(file, "utf8")), source: file };
  }
  return null;
}

function pathMethods(spec) {
  // { "/v1/devices": ["get","post"], ... } — the contract surface we care about.
  const out = {};
  for (const [p, ops] of Object.entries(spec.paths ?? {})) {
    out[p] = Object.keys(ops)
      .filter((m) => ["get", "post", "put", "delete", "patch"].includes(m))
      .sort();
  }
  return out;
}

function diffSurfaces(snap, ref) {
  const problems = [];
  if (snap.info?.version !== ref.info?.version) {
    problems.push(`version: snapshot ${snap.info?.version} vs gateway ${ref.info?.version}`);
  }
  const sp = pathMethods(snap);
  const rp = pathMethods(ref);
  for (const p of Object.keys(rp))
    if (!(p in sp)) problems.push(`path present on gateway but missing from snapshot: ${p} [${rp[p]}]`);
  for (const p of Object.keys(sp)) {
    if (!(p in rp)) problems.push(`path in snapshot but gone from gateway: ${p} [${sp[p]}]`);
    else if (sp[p].join(",") !== rp[p].join(","))
      problems.push(`methods differ for ${p}: snapshot [${sp[p]}] vs gateway [${rp[p]}]`);
  }
  return problems;
}

const ref = await loadReference();
if (!ref) {
  console.log("check:spec — skipped (set GATEWAY_OPENAPI_URL or GATEWAY_OPENAPI_FILE to enforce drift detection).");
  process.exit(0);
}

const snapshot = JSON.parse(await readFile(SNAPSHOT, "utf8"));
const problems = diffSurfaces(snapshot, ref.spec);

if (problems.length === 0) {
  console.log(`check:spec — OK. Snapshot matches gateway contract (${ref.source}, v${ref.spec.info?.version}).`);
  process.exit(0);
}

console.error(`check:spec — DRIFT DETECTED against ${ref.source}:`);
for (const p of problems) console.error(`  - ${p}`);
console.error("\nRefresh the snapshot if this change is intended:");
console.error("  curl -s <gateway>/openapi.json | python -m json.tool > gateway.openapi.json && npm run gen:types");
process.exit(1);
