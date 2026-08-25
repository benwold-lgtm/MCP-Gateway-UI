// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { DeviceType, DeviceTypeDetail, UpstreamKind } from "../types";
import { health, ui } from "../tokens";

/** Device-type curation and per-tenant assignment (ADR-0020 §1/§2).
 *
 * Not gated on a live act-on-tenant grant, unlike Devices/Monitoring/Backup: curating the
 * catalog and assigning a type to a tenant are provider-plane acts on the provider's OWN
 * storage — assignment is an *offer*, never a write into any tenant's registry (§2). This is
 * deliberately minimal: a list, a create form, a version form, and an assign/revoke-by-id
 * form — enough to exercise the whole slice 3 relay, not a finished curation UI.
 *
 * A device type is a **template only**: no host, no credential, no tenant. `spec_path`
 * (openapi only) is relative to whatever `base_url` a tenant supplies later, at claim
 * time (slice 4) — never an absolute URL.
 */
export function CatalogConsole() {
  const [types, setTypes] = useState<DeviceType[]>([]);
  const [selected, setSelected] = useState<DeviceTypeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const { device_types } = await api.provider.catalog.listDeviceTypes();
      setTypes(device_types);
      setError(null);
    } catch (err) {
      // Not the same as "nothing curated yet" (ADR-0020 §7) — said plainly rather than
      // rendering an empty list indistinguishable from a provider who has curated none.
      setError(err instanceof ApiError ? err.message : "Could not reach the catalog service");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const openType = useCallback(async (id: string) => {
    try {
      setSelected(await api.provider.catalog.getDeviceType(id));
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not read this device type");
    }
  }, []);

  return (
    <div style={{ display: "grid", gap: 16, maxWidth: 720 }}>
      {error && <p style={{ color: health.fail }}>{error}</p>}

      <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
        <h2 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>Device types</h2>
        {/* An empty list only ever means "nothing curated" when the read actually
            succeeded — on a failed read `error` above already says so, and rendering
            this too would make the two indistinguishable (ADR-0020 §7). */}
        {error ? null : types.length === 0 ? (
          <p style={{ margin: 0, color: ui.muted }}>Nothing curated yet.</p>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 4 }}>
            {types.map((t) => (
              <li key={t.id}>
                <button
                  onClick={() => void openType(t.id)}
                  style={{
                    background: "none",
                    border: 0,
                    padding: "2px 0",
                    cursor: "pointer",
                    color: ui.ink,
                  }}
                >
                  <strong>{t.slug}</strong> — {t.name} (v{t.latest_version})
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <CreateDeviceType onCreated={load} />

      {selected && (
        <DeviceTypeDetailPanel detail={selected} onChanged={() => void openType(selected.id).then(load)} />
      )}
    </div>
  );
}

function CreateDeviceType({ onCreated }: { onCreated: () => void | Promise<void> }) {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [upstreamKind, setUpstreamKind] = useState<UpstreamKind>("openapi");
  const [specPath, setSpecPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.provider.catalog.createDeviceType({
        slug: slug.trim(),
        name: name.trim(),
        description: description.trim() || undefined,
        upstream_kind: upstreamKind,
        spec_path: upstreamKind === "openapi" && specPath.trim() ? specPath.trim() : undefined,
      });
      setSlug("");
      setName("");
      setDescription("");
      setSpecPath("");
      await onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the device type");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <h2 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>Curate a device type</h2>
      <form onSubmit={create} style={{ display: "grid", gap: 8 }}>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Slug</span>
          <input
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            placeholder="acme-sensor-x1"
            required
          />
        </label>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme Sensor X1"
            required
          />
        </label>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Description</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Upstream kind</span>
          <select value={upstreamKind} onChange={(e) => setUpstreamKind(e.target.value as UpstreamKind)}>
            <option value="openapi">openapi</option>
            <option value="mcp">mcp</option>
          </select>
        </label>
        {upstreamKind === "openapi" && (
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>
              Spec path (relative to the tenant's base_url at claim time)
            </span>
            <input
              value={specPath}
              onChange={(e) => setSpecPath(e.target.value)}
              placeholder="/openapi.json"
            />
          </label>
        )}
        {error && <p style={{ margin: 0, color: health.fail, fontSize: "0.85em" }}>{error}</p>}
        <button
          type="submit"
          disabled={busy || !slug.trim() || !name.trim()}
          style={{ justifySelf: "start" }}
        >
          Create
        </button>
      </form>
    </section>
  );
}

function DeviceTypeDetailPanel({
  detail,
  onChanged,
}: {
  detail: DeviceTypeDetail;
  onChanged: () => void | Promise<void>;
}) {
  const [tenantId, setTenantId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function assign() {
    setBusy(true);
    setError(null);
    try {
      await api.provider.catalog.assign(detail.id, tenantId.trim());
      await onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not assign");
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      await api.provider.catalog.revoke(detail.id, tenantId.trim());
      await onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not revoke");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ border: `1px solid ${ui.rule}`, borderRadius: 6, padding: "12px 16px" }}>
      <h2 style={{ marginTop: 0, fontSize: "1.05em", color: ui.ink }}>{detail.slug} — version history</h2>
      <ul style={{ listStyle: "none", margin: "0 0 12px", padding: 0, display: "grid", gap: 4 }}>
        {detail.versions.map((v) => (
          <li key={v.id} style={{ color: ui.inkSoft, fontSize: "0.9em" }}>
            v{v.version} — {v.upstream_kind}
            {v.spec_path ? ` (${v.spec_path})` : ""}
            {v.changelog ? `: ${v.changelog}` : ""}
          </li>
        ))}
      </ul>

      <div style={{ display: "grid", gap: 8, maxWidth: 360 }}>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: "0.85em", color: ui.inkSoft }}>Tenant id</span>
          <input value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="mcp-t-…" />
        </label>
        {error && <p style={{ margin: 0, color: health.fail, fontSize: "0.85em" }}>{error}</p>}
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => void assign()} disabled={busy || !tenantId.trim()}>
            Assign
          </button>
          <button onClick={() => void revoke()} disabled={busy || !tenantId.trim()}>
            Revoke
          </button>
        </div>
      </div>
    </section>
  );
}
