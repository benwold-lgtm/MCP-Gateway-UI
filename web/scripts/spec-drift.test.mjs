// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 Ben Wold. All rights reserved.
//
// Tests for the contract drift guard — which had never had any, and had a hole in it.
//
// A guard nobody has watched fail is a guard nobody knows the shape of. This one compared
// paths and methods and `info.version`, and read as a passing check for two gateway releases
// while the payload contract moved underneath it. The tests below are written against the
// drift that actually happened, plus the two neighbouring cases that would fool a version
// check on its own.
//
// Lives in `scripts/` as `.mjs` deliberately: `tsconfig.json` includes only `src`, so a `.ts`
// test importing this `.mjs` module would fail `npm run typecheck`.
import { describe, it, expect } from "vitest";

import { diffSurfaces, pathMethods, schemaShapes } from "./spec-drift.mjs";

const base = {
  info: { version: "0.3.5" },
  paths: { "/v1/devices": { get: {}, post: {} } },
  components: {
    schemas: {
      DeviceSummary: {
        properties: { hostname: {}, reachable: {} },
        required: ["hostname"],
      },
    },
  },
};

const clone = (o) => JSON.parse(JSON.stringify(o));

describe("schemaShapes", () => {
  it("reads property names and required, sorted", () => {
    expect(schemaShapes(base)).toEqual({
      DeviceSummary: { props: ["hostname", "reachable"], required: ["hostname"] },
    });
  });

  it("tolerates a schema with no properties and a spec with no components", () => {
    expect(schemaShapes({ components: { schemas: { Empty: {} } } })).toEqual({
      Empty: { props: [], required: [] },
    });
    expect(schemaShapes({})).toEqual({});
  });
});

describe("diffSurfaces", () => {
  it("is silent when the two agree", () => {
    expect(diffSurfaces(clone(base), clone(base))).toEqual([]);
  });

  it("catches the drift that actually happened", () => {
    // The gateway added `credential_state` to DeviceSummary (ADR-0018 §3) and the committed
    // snapshot went stale. Paths and methods were identical throughout — this is precisely
    // the drift the guard used to be blind to.
    const gateway = clone(base);
    gateway.components.schemas.DeviceSummary.properties.credential_state = {};

    const problems = diffSurfaces(clone(base), gateway);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("DeviceSummary");
    expect(problems[0]).toContain("credential_state");
  });

  it("catches it even when the versions match", () => {
    // The case that makes the schema diff load-bearing rather than redundant. `info.version`
    // comes from installed package metadata, so a spec generated against a stale editable
    // install reports the OLD version — the two would agree and the version check would say
    // nothing at all. That is not hypothetical; it is how this snapshot was first generated.
    const snap = clone(base);
    const gateway = clone(base);
    gateway.components.schemas.DeviceSummary.properties.credential_state = {};

    expect(snap.info.version).toBe(gateway.info.version);
    expect(diffSurfaces(snap, gateway)).toHaveLength(1);
  });

  it("catches a field REMOVED from the gateway, not just an added one", () => {
    // The direction that breaks a running console rather than merely under-serving it: the UI
    // still reads a field nothing sends any more.
    const gateway = clone(base);
    delete gateway.components.schemas.DeviceSummary.properties.reachable;

    const problems = diffSurfaces(clone(base), gateway);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("gone from gateway");
    expect(problems[0]).toContain("reachable");
  });

  it("catches a field becoming required, which adds and removes nothing", () => {
    // `openapi-typescript` renders a schema default as a REQUIRED property, so this flips what
    // the generated types demand of every call site while the property list is unchanged.
    const gateway = clone(base);
    gateway.components.schemas.DeviceSummary.required = ["hostname", "reachable"];

    const problems = diffSurfaces(clone(base), gateway);
    expect(problems).toEqual([expect.stringContaining("newly REQUIRED")]);
  });

  it("catches a whole schema appearing or disappearing", () => {
    const added = clone(base);
    added.components.schemas.CatalogEntry = { properties: {} };
    expect(diffSurfaces(clone(base), added)).toEqual([
      expect.stringContaining("schema present on gateway but missing from snapshot: CatalogEntry"),
    ]);

    expect(diffSurfaces(added, clone(base))).toEqual([
      expect.stringContaining("schema in snapshot but gone from gateway: CatalogEntry"),
    ]);
  });

  it("still catches path and method drift", () => {
    // Regression guard for the failure this script was written for in the first place: the
    // BFF calling pre-/v1 paths. Extending the check must not cost the original one.
    const gateway = clone(base);
    gateway.paths["/v1/catalog"] = { get: {} };
    delete gateway.paths["/v1/devices"].post;

    const problems = diffSurfaces(clone(base), gateway);
    expect(problems).toEqual(
      expect.arrayContaining([
        expect.stringContaining("/v1/catalog"),
        expect.stringContaining("methods differ for /v1/devices"),
      ]),
    );
  });

  it("reports a version change on its own", () => {
    const gateway = clone(base);
    gateway.info.version = "0.4.0";
    expect(diffSurfaces(clone(base), gateway)).toEqual([expect.stringContaining("0.3.5")]);
  });
});

describe("pathMethods", () => {
  it("ignores non-operation keys like parameters and servers", () => {
    const spec = { paths: { "/x": { get: {}, parameters: [], servers: [] } } };
    expect(pathMethods(spec)).toEqual({ "/x": ["get"] });
  });
});
