// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { AuthKind, ClaimPayload, DeviceType, DeviceTypeDetail } from "../types";
import { health, ui } from "../tokens";

/** ADR-0020 §4: claim one of this tenant's assigned device types into their own registry.
 *
 * Only the tenant's own half of a device record is asked for here — hostname, base_url,
 * and a credential shaped by the claimed type's `auth_kind`. Everything else (transport,
 * upstream_kind, spec_path, fingerprint_policy) comes from the type's current curated
 * version; the BFF fills it in server-side, so this form never even sees those fields,
 * let alone lets them be overridden.
 *
 * Deliberately separate from DeviceForm: this does not touch or gate free-type
 * registration, which keeps working exactly as it does today.
 */
export function ClaimFromCatalog({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [types, setTypes] = useState<DeviceType[] | null>(null);
  const [selected, setSelected] = useState<DeviceTypeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.catalog
      .listAssigned()
      .then(({ device_types }) => active && setTypes(device_types))
      .catch(
        (err) => active && setError(err instanceof ApiError ? err.message : "Could not reach the catalog"),
      );
    return () => {
      active = false;
    };
  }, []);

  async function open(id: string) {
    setError(null);
    try {
      setSelected(await api.catalog.getDeviceType(id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not read this device type");
    }
  }

  return (
    <section
      style={{
        border: `1px solid ${ui.rule}`,
        borderRadius: 8,
        padding: "12px 16px",
        margin: "12px 0",
        background: "#fff",
      }}
    >
      <h3 style={{ marginTop: 0 }}>Claim from catalog</h3>
      {error && <p style={{ color: health.fail }}>{error}</p>}

      {!selected &&
        (error ? null : types === null ? (
          <p style={{ margin: 0, color: ui.muted }}>Loading…</p>
        ) : types.length === 0 ? (
          <p style={{ margin: 0, color: ui.muted }}>Nothing assigned to this tenant yet.</p>
        ) : (
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 4 }}>
            {types.map((t) => (
              <li key={t.id}>
                <button
                  onClick={() => void open(t.id)}
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
        ))}

      {selected && <ClaimForm detail={selected} onDone={onDone} onBack={() => setSelected(null)} />}

      {!selected && (
        <div style={{ marginTop: 12 }}>
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      )}
    </section>
  );
}

function ClaimForm({
  detail,
  onDone,
  onBack,
}: {
  detail: DeviceTypeDetail;
  onDone: () => void;
  onBack: () => void;
}) {
  const current = detail.versions[detail.versions.length - 1];
  const authKind: AuthKind = current.auth_kind;

  const [hostname, setHostname] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  // ADR-0020 §4c: the type declares who supplies the address. `provider_fixed` means the
  // provider curated it, so the field is not asked for at all rather than pre-filled and
  // locked — a disabled input still looks like something the tenant chose, and the BFF
  // refuses a tenant-supplied address on these types rather than ignoring it.
  //
  // Says nothing about the credential: everything below this stays exactly as it was. A
  // host-fixed type is not a provider-operated service (§6); the tenant still brings their
  // own key.
  const hostIsFixed = current.host_source === "provider_fixed";
  const fixedBaseUrl = current.fixed_base_url ?? null;
  // Pre-filled from the curated recommendation. Editable, and a tenant who changes it is
  // obeyed — it is a recommendation, not a ceiling (ADR-0020 §2).
  const [rateLimit, setRateLimit] = useState(
    current.recommended_rate_limit_rps != null ? String(current.recommended_rate_limit_rps) : "",
  );
  const [expectedSpki, setExpectedSpki] = useState("");
  // api_key
  const [apiKey, setApiKey] = useState("");
  // Curated when the provider has said, asked for when they have not. The old default was a
  // hardcoded "X-API-Key" — a plausible guess that is wrong for plenty of appliances and
  // fails as a 401 at first contact, reading like a bad key rather than a misplaced one.
  const curatedKeyName = current.api_key_name ?? null;
  const curatedKeyLocation = current.api_key_location ?? null;
  const [apiKeyName, setApiKeyName] = useState(curatedKeyName ?? "X-API-Key");
  const [apiKeyLocation, setApiKeyLocation] = useState(curatedKeyLocation ?? "header");
  // oauth2
  const [tokenEndpoint, setTokenEndpoint] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    const body: ClaimPayload = { hostname: hostname.trim() };
    // Omitted entirely for a host-fixed type — the BFF treats a supplied address as a
    // disagreement about where the device is, not as noise to override.
    if (!hostIsFixed) body.base_url = baseUrl.trim();
    if (rateLimit.trim()) body.rate_limit_rps = Number(rateLimit);
    if (expectedSpki.trim()) body.expected_tls_spki_sha256 = expectedSpki.trim();
    if (authKind === "api_key") {
      body.auth = { api_key: apiKey, location: apiKeyLocation, name: apiKeyName };
    } else if (authKind === "oauth2") {
      body.auth = { token_endpoint: tokenEndpoint, client_id: clientId, client_secret: clientSecret };
    }
    try {
      await api.catalog.claim(detail.id, body);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not claim this device type");
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ marginTop: 8 }}>
      <p style={{ margin: "0 0 12px", color: ui.inkSoft, fontSize: "0.9em" }}>
        Claiming <strong>{detail.name || detail.slug}</strong> v{current.version}. Its transport, upstream
        shape and fingerprint policy come from the curated type.{" "}
        {hostIsFixed ? (
          <>
            <strong>The credentials below are yours</strong> — your provider does not supply them and never
            sees them. This type&apos;s address is part of the curated type.
          </>
        ) : (
          <>
            <strong>The address and credentials below are yours</strong> — your provider does not supply them
            and never sees them.
          </>
        )}
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "140px 1fr",
          gap: 8,
          alignItems: "center",
          maxWidth: 560,
        }}
      >
        <label htmlFor="cc-hostname" style={{ color: ui.inkSoft, fontSize: 14 }}>
          Name for this device
        </label>
        <input
          id="cc-hostname"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          required
          placeholder="e.g. prism-dc1"
          aria-describedby="cc-hostname-help"
        />
        <span />
        <span id="cc-hostname-help" style={{ fontSize: "0.8em", color: ui.muted }}>
          How it appears in your fleet. Yours to choose — it need not be the appliance&apos;s DNS name.
        </span>

        {hostIsFixed ? (
          <>
            <span style={{ color: ui.inkSoft, fontSize: 14 }}>Address</span>
            <span data-testid="cc-host-fixed" style={{ fontSize: 14 }}>
              <code>{fixedBaseUrl}</code>
            </span>
          </>
        ) : (
          <>
            <label htmlFor="cc-base-url" style={{ color: ui.inkSoft, fontSize: 14 }}>
              Address
            </label>
            <input
              id="cc-base-url"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              required
              placeholder="e.g. https://prism.example.internal:9440"
              aria-describedby="cc-base-url-help"
            />
          </>
        )}
        <span />
        <span id="cc-base-url-help" style={{ fontSize: "0.8em", color: ui.muted }}>
          {hostIsFixed ? (
            <>
              Supplied by your provider as part of this device type. Your gateway still reaches it with{" "}
              <em>your</em> credentials, and pins its certificate on first contact like any other device.
            </>
          ) : (
            <>
              Scheme, host and port of <em>your</em> appliance. Reached from your own gateway, so a private
              address is fine.
            </>
          )}
        </span>

        <label htmlFor="cc-rate" style={{ color: ui.inkSoft, fontSize: 14 }}>
          Rate limit
        </label>
        <input
          id="cc-rate"
          type="number"
          min="0"
          step="0.1"
          value={rateLimit}
          onChange={(e) => setRateLimit(e.target.value)}
          placeholder="(none) — requests per second"
        />

        <label htmlFor="cc-spki" style={{ color: ui.inkSoft, fontSize: 14 }}>
          Pin the TLS certificate
        </label>
        <input
          id="cc-spki"
          value={expectedSpki}
          onChange={(e) => setExpectedSpki(e.target.value)}
          placeholder="(optional) base64 SHA-256 of the public key"
        />

        {authKind === "api_key" && (
          <>
            <label htmlFor="cc-api-key" style={{ color: ui.inkSoft, fontSize: 14 }}>
              API key
            </label>
            <input
              id="cc-api-key"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              required
            />
            {/* Stated, not asked, when the provider has curated it — the BFF overrides
                whatever is sent anyway, so an editable control here would be a field that
                appears to do something and does not. Shown rather than hidden because an
                operator debugging a 401 needs to know where the key is going. */}
            {curatedKeyLocation && curatedKeyName ? (
              <>
                <span style={{ color: ui.inkSoft, fontSize: 14 }}>Sent as</span>
                <span data-testid="cc-api-curated">
                  <code>{curatedKeyName}</code> in the {curatedKeyLocation}
                  <span style={{ color: ui.muted }}> — set by your provider</span>
                </span>
              </>
            ) : (
              <>
                <label htmlFor="cc-api-loc" style={{ color: ui.inkSoft, fontSize: 14 }}>
                  Location
                </label>
                <select
                  id="cc-api-loc"
                  value={apiKeyLocation}
                  onChange={(e) => setApiKeyLocation(e.target.value as "header" | "query" | "cookie")}
                >
                  <option value="header">header</option>
                  <option value="query">query</option>
                  <option value="cookie">cookie</option>
                </select>
                <label htmlFor="cc-api-name" style={{ color: ui.inkSoft, fontSize: 14 }}>
                  Name
                </label>
                <input id="cc-api-name" value={apiKeyName} onChange={(e) => setApiKeyName(e.target.value)} />
              </>
            )}
          </>
        )}

        {authKind === "oauth2" && (
          <>
            <label htmlFor="cc-oauth-token" style={{ color: ui.inkSoft, fontSize: 14 }}>
              Token endpoint
            </label>
            <input
              id="cc-oauth-token"
              value={tokenEndpoint}
              onChange={(e) => setTokenEndpoint(e.target.value)}
              required
            />
            <label htmlFor="cc-oauth-cid" style={{ color: ui.inkSoft, fontSize: 14 }}>
              Client ID
            </label>
            <input
              id="cc-oauth-cid"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              required
            />
            <label htmlFor="cc-oauth-secret" style={{ color: ui.inkSoft, fontSize: 14 }}>
              Client secret
            </label>
            <input
              id="cc-oauth-secret"
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              required
            />
          </>
        )}
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center" }}>
        <button type="submit" disabled={submitting}>
          Claim
        </button>
        <button type="button" onClick={onBack} disabled={submitting}>
          Back
        </button>
        {error && <span style={{ color: health.fail }}>{error}</span>}
      </div>
    </form>
  );
}
