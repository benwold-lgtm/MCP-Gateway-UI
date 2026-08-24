// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 Ben Wold. All rights reserved.
//
// Contract drift guard: compares the committed gateway OpenAPI snapshot
// (web/gateway.openapi.json) against a live/reference gateway spec, so the UI's vendored
// contract can't silently rot out of sync with the gateway (the exact failure that left the
// BFF calling pre-/v1 paths). The comparison itself lives in ./spec-drift.mjs so it can be
// tested; this file is the CLI around it.
//
// Source of the reference spec (first one set wins):
//   GATEWAY_OPENAPI_URL   e.g. http://localhost:8000/openapi.json   (fetched)
//   GATEWAY_OPENAPI_FILE  path to an openapi.json on disk
//
// ⚠️ With neither set the check **does not run**. That default is deliberate — ordinary CI
// has no gateway to compare against — but it means a green `check:spec` line in a CI log is
// usually the sound of nothing happening. Set CHECK_SPEC_REQUIRED=1 in any job that is
// supposed to enforce this, and a missing reference becomes a failure instead of a shrug.
//
// Usage:  node scripts/check-spec-drift.mjs   (or: npm run check:spec)
// Refresh the snapshot when drift is intentional:
//   curl -s http://localhost:8000/openapi.json | python -m json.tool > gateway.openapi.json
//   npm run gen:types

import { readFile } from "node:fs/promises";
import { diffSurfaces } from "./spec-drift.mjs";

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

const ref = await loadReference();
if (!ref) {
  if (process.env.CHECK_SPEC_REQUIRED) {
    console.error(
      "check:spec — NOT RUN, and this job requires it (CHECK_SPEC_REQUIRED is set).\n" +
        "  Point GATEWAY_OPENAPI_URL or GATEWAY_OPENAPI_FILE at a gateway spec.",
    );
    process.exit(1);
  }
  // Worded as "did not run" rather than "skipped": a log line saying "skipped" next to a
  // green tick reads as a check that passed, which is how a stale snapshot survived two
  // releases without anybody noticing.
  console.log(
    "check:spec — DID NOT RUN (no reference gateway). Drift was NOT checked.\n" +
      "  Set GATEWAY_OPENAPI_URL or GATEWAY_OPENAPI_FILE to compare against a real gateway.",
  );
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
