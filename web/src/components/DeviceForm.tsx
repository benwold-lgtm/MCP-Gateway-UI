// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { DevicePayload } from "../types";

// Register (POST) or edit (PUT) a device, including auth — so an *authenticated*
// device can be onboarded from the UI. On edit, fields are pre-filled from the
// gateway; credentials are never returned, so auth defaults to "(unchanged)", which
// omits `auth` from the PUT and the gateway preserves the stored credentials.
type AuthChoice = "unchanged" | "none" | "api_key" | "oauth2";

export function DeviceForm({
  mode,
  hostname: editHostname,
  onDone,
  onCancel,
}: {
  mode: "create" | "edit";
  hostname?: string;
  onDone: () => void;
  onCancel: () => void;
}) {
  const isEdit = mode === "edit";
  const [hostname, setHostname] = useState(editHostname ?? "");
  const [baseUrl, setBaseUrl] = useState("");
  const [specUrl, setSpecUrl] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [authType, setAuthType] = useState<AuthChoice>(isEdit ? "unchanged" : "none");
  // api_key
  const [apiKey, setApiKey] = useState("");
  const [apiKeyName, setApiKeyName] = useState("X-API-Key");
  const [apiKeyLocation, setApiKeyLocation] = useState("header");
  const [apiKeyPrefix, setApiKeyPrefix] = useState("");
  // oauth2
  const [tokenEndpoint, setTokenEndpoint] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [scopes, setScopes] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(isEdit);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!isEdit || !editHostname) return;
    let active = true;
    api
      .getDevice(editHostname)
      .then((d) => {
        if (!active) return;
        setBaseUrl(d.base_url ?? "");
        setSpecUrl(d.spec_url ?? "");
        setRateLimit(d.rate_limit_rps != null ? String(d.rate_limit_rps) : "");
      })
      .catch((err) => active && setError(err instanceof ApiError ? err.message : "Failed to load device"))
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [isEdit, editHostname]);

  function buildPayload(): DevicePayload {
    const p: DevicePayload = {};
    if (!isEdit) p.hostname = hostname.trim();
    if (baseUrl.trim()) p.base_url = baseUrl.trim();
    if (specUrl.trim()) p.spec_url = specUrl.trim();
    p.transport = "sse";
    if (rateLimit.trim()) p.rate_limit_rps = Number(rateLimit);
    if (authType === "none") {
      p.auth_type = "none";
    } else if (authType === "api_key") {
      p.auth_type = "api_key";
      p.auth = {
        api_key: apiKey,
        location: apiKeyLocation,
        name: apiKeyName,
        ...(apiKeyPrefix ? { value_prefix: apiKeyPrefix } : {}),
      };
    } else if (authType === "oauth2") {
      p.auth_type = "oauth2";
      p.auth = {
        token_endpoint: tokenEndpoint,
        client_id: clientId,
        client_secret: clientSecret,
        ...(scopes.trim()
          ? {
              scopes: scopes
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            }
          : {}),
      };
    }
    // "unchanged" → omit auth_type/auth so the gateway keeps the stored credentials.
    return p;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const payload = buildPayload();
      if (isEdit) await api.updateDevice(editHostname!, payload);
      else await api.registerDevice(payload);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save device");
      setSubmitting(false);
    }
  }

  if (loading) return <p>Loading device…</p>;

  return (
    <form
      onSubmit={submit}
      style={{
        border: "1px solid #ccc",
        borderRadius: 8,
        padding: "12px 16px",
        margin: "12px 0",
        background: "#fff",
      }}
    >
      <h3 style={{ marginTop: 0 }}>{isEdit ? `Edit ${editHostname}` : "Register device"}</h3>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "140px 1fr",
          gap: 8,
          alignItems: "center",
          maxWidth: 560,
        }}
      >
        {!isEdit && (
          <Field label="Hostname" htmlFor="df-hostname">
            <input
              id="df-hostname"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              required
              placeholder="my-sensor"
            />
          </Field>
        )}
        <Field label="Base URL" htmlFor="df-base-url">
          <input
            id="df-base-url"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            required
            placeholder="http://device.local"
          />
        </Field>
        <Field label="Spec URL" htmlFor="df-spec-url">
          <input
            id="df-spec-url"
            value={specUrl}
            onChange={(e) => setSpecUrl(e.target.value)}
            placeholder="(auto-discovered if blank)"
          />
        </Field>
        <Field label="Rate limit (rps)" htmlFor="df-rate">
          <input
            id="df-rate"
            type="number"
            min="0"
            step="0.1"
            value={rateLimit}
            onChange={(e) => setRateLimit(e.target.value)}
            placeholder="(none)"
          />
        </Field>

        <Field label="Auth" htmlFor="df-auth">
          <select id="df-auth" value={authType} onChange={(e) => setAuthType(e.target.value as AuthChoice)}>
            {isEdit && <option value="unchanged">(unchanged)</option>}
            <option value="none">none</option>
            <option value="api_key">api_key</option>
            <option value="oauth2">oauth2</option>
          </select>
        </Field>

        {authType === "api_key" && (
          <>
            <Field label="API key" htmlFor="df-api-key">
              <input
                id="df-api-key"
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                required
              />
            </Field>
            <Field label="Location" htmlFor="df-api-loc">
              <select
                id="df-api-loc"
                value={apiKeyLocation}
                onChange={(e) => setApiKeyLocation(e.target.value)}
              >
                <option value="header">header</option>
                <option value="query">query</option>
                <option value="cookie">cookie</option>
              </select>
            </Field>
            <Field label="Name" htmlFor="df-api-name">
              <input
                id="df-api-name"
                value={apiKeyName}
                onChange={(e) => setApiKeyName(e.target.value)}
                placeholder="X-API-Key"
              />
            </Field>
            <Field label="Value prefix" htmlFor="df-api-prefix">
              <input
                id="df-api-prefix"
                value={apiKeyPrefix}
                onChange={(e) => setApiKeyPrefix(e.target.value)}
                placeholder='e.g. "Bearer "'
              />
            </Field>
          </>
        )}

        {authType === "oauth2" && (
          <>
            <Field label="Token endpoint" htmlFor="df-oauth-token">
              <input
                id="df-oauth-token"
                value={tokenEndpoint}
                onChange={(e) => setTokenEndpoint(e.target.value)}
                required
              />
            </Field>
            <Field label="Client ID" htmlFor="df-oauth-cid">
              <input
                id="df-oauth-cid"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                required
              />
            </Field>
            <Field label="Client secret" htmlFor="df-oauth-secret">
              <input
                id="df-oauth-secret"
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                required
              />
            </Field>
            <Field label="Scopes" htmlFor="df-oauth-scopes">
              <input
                id="df-oauth-scopes"
                value={scopes}
                onChange={(e) => setScopes(e.target.value)}
                placeholder="comma,separated"
              />
            </Field>
          </>
        )}
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center" }}>
        <button type="submit" disabled={submitting}>
          {isEdit ? "Save changes" : "Register"}
        </button>
        <button type="button" onClick={onCancel} disabled={submitting}>
          Cancel
        </button>
        {error && <span style={{ color: "crimson" }}>{error}</span>}
      </div>
    </form>
  );
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: React.ReactNode }) {
  return (
    <>
      <label htmlFor={htmlFor} style={{ color: "#555", fontSize: 14 }}>
        {label}
      </label>
      {children}
    </>
  );
}
