// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 Ben Wold. All rights reserved.
//
// The comparison behind `check:spec`, separated from the CLI that runs it so it can be
// tested. A drift guard nobody has watched fail is a guard nobody knows the shape of — and
// this one had a hole in it for exactly that reason (see `schemaShapes`).

/** `{ "/v1/devices": ["get","post"], … }` — the routing surface. */
export function pathMethods(spec) {
  const out = {};
  for (const [p, ops] of Object.entries(spec.paths ?? {})) {
    out[p] = Object.keys(ops)
      .filter((m) => ["get", "post", "put", "delete", "patch"].includes(m))
      .sort();
  }
  return out;
}

/** `{ DeviceSummary: { props: [...], required: [...] }, … }` — the *payload* surface.
 *
 * This is the half the guard did not look at, and the omission had a real cost: the gateway
 * added `credential_state` to `DeviceSummary` and `DeviceDetail`, the committed snapshot went
 * two releases stale, and nothing anywhere said so. Paths and methods were identical the whole
 * time — the drift was entirely inside the schemas.
 *
 * `required` is tracked alongside the property names because moving a field into or out of it
 * changes what the generated TypeScript demands of every call site, without adding or removing
 * anything from the list.
 */
export function schemaShapes(spec) {
  const out = {};
  for (const [name, schema] of Object.entries(spec.components?.schemas ?? {})) {
    out[name] = {
      props: Object.keys(schema.properties ?? {}).sort(),
      required: [...(schema.required ?? [])].sort(),
    };
  }
  return out;
}

function diffLists(a, b) {
  const added = b.filter((x) => !a.includes(x));
  const removed = a.filter((x) => !b.includes(x));
  return { added, removed };
}

export function diffSurfaces(snap, ref) {
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

  const ss = schemaShapes(snap);
  const rs = schemaShapes(ref);
  for (const name of Object.keys(rs))
    if (!(name in ss)) problems.push(`schema present on gateway but missing from snapshot: ${name}`);
  for (const name of Object.keys(ss)) {
    if (!(name in rs)) {
      problems.push(`schema in snapshot but gone from gateway: ${name}`);
      continue;
    }
    const props = diffLists(ss[name].props, rs[name].props);
    if (props.added.length) problems.push(`${name}: field(s) added on gateway, absent from snapshot: ${props.added}`);
    if (props.removed.length) problems.push(`${name}: field(s) in snapshot but gone from gateway: ${props.removed}`);

    const req = diffLists(ss[name].required, rs[name].required);
    if (req.added.length) problems.push(`${name}: field(s) newly REQUIRED on gateway: ${req.added}`);
    if (req.removed.length) problems.push(`${name}: field(s) no longer required on gateway: ${req.removed}`);
  }

  return problems;
}
