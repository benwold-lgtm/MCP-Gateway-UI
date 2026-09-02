// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { DevicePayload, UpstreamKind } from "../types";
import { health, ui } from "../tokens";

// Register (POST) or edit (PUT) a device, including auth — so an *authenticated*
// device can be onboarded from the UI. On edit, fields are pre-filled from the
// gateway; credentials are never returned, so auth defaults to "(unchanged)", which
// omits `auth` from the PUT and the gateway preserves the stored credentials.
//
// This form is the console's only route to `POST /devices`, so every field the gateway
// accepts at registration and cannot be given later has to be reachable here. Two are:
// `upstream_kind`, without which an MCP server can only be registered by hand against the
// API and lands mislabelled as an OpenAPI device; and ADR-0015 §8's pre-pin, which closes
// the TOFU window only if it is supplied in the same call that creates the device.
type AuthChoice = "unchanged" | "none" | "api_key" | "oauth2";

const SPKI_RE = /^[0-9a-f]{64}$/;

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
  const [upstreamKind, setUpstreamKind] = useState<UpstreamKind>("openapi");
  const [specUrl, setSpecUrl] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  // Registration-only (see `DevicePayload`): the gateway's PUT parses neither, so offering
  // them on an edit would be a control that reports success and changes nothing.
  const [expectedSpki, setExpectedSpki] = useState("");
  const [fingerprintPolicy, setFingerprintPolicy] = useState("");
  // What the gateway reported, so an edit can tell "left alone" from "deliberately emptied".
  // Sending the policy unconditionally would be wrong in the same way sending `spec_url`
  // unconditionally is: it turns every unrelated edit into a statement about a field the
  // operator never touched.
  const [loadedPolicy, setLoadedPolicy] = useState("");
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
        // A gateway older than ADR-0009 omits the field entirely; its schema default is
        // "openapi", which is also the only thing such a gateway can be serving.
        setUpstreamKind(d.upstream_kind === "mcp" ? "mcp" : "openapi");
        setSpecUrl(d.spec_url ?? "");
        setFingerprintPolicy(d.fingerprint_policy ?? "");
        setLoadedPolicy(d.fingerprint_policy ?? "");
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
    p.upstream_kind = upstreamKind;
    if (upstreamKind === "openapi") {
      if (specUrl.trim()) p.spec_url = specUrl.trim();
      // Same null-vs-absent rule, for the same reason: on an edit the field is pre-filled
      // from the gateway, so an empty box means the operator cleared it. Omitting the key
      // would carry the old value forward and leave a spec URL the form says is gone.
      else if (isEdit) p.spec_url = null;
    } else {
      // Explicit null, not omission. On a PUT the gateway preserves a stored `spec_url` when
      // the key is absent, so switching an existing OpenAPI device to mcp without this sends
      // the old spec URL along with the new kind and is refused. Sending null on a create is
      // equivalent to omitting it, so one rule covers both modes.
      p.spec_url = null;
    }
    // `upstream_transport` is deliberately never sent — see `DevicePayload`.
    p.transport = "sse";
    if (rateLimit.trim()) p.rate_limit_rps = Number(rateLimit);
    // The pin stays create-only: the gateway now REFUSES it on an update rather than
    // ignoring it, because writing a key here is the quiet version of laundering one past
    // the pin. Re-pinning has its own approval flow on the device detail screen.
    if (!isEdit && expectedSpki.trim()) {
      p.expected_tls_spki_sha256 = expectedSpki.trim().toLowerCase();
    }
    // The policy is editable in both modes. Sent whenever it differs from what the gateway
    // reported, INCLUDING when it has been emptied — the gateway reads an explicit null as
    // "clear the override and inherit the fleet default", which is a different state from
    // `warn` and the only way back out of a per-device setting.
    if (!isEdit) {
      if (fingerprintPolicy) p.fingerprint_policy = fingerprintPolicy as "warn" | "enforce";
    } else if (fingerprintPolicy !== loadedPolicy) {
      p.fingerprint_policy = fingerprintPolicy ? (fingerprintPolicy as "warn" | "enforce") : null;
    }
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
    // Checked here as well as on the gateway, and the duplication is the point: a rejected
    // digest is a rejected REGISTRATION, and the operator's next move is a retry that now
    // collides with nothing — the device was never created. Catching it before the request
    // keeps that round trip out of the common typo.
    if (!isEdit && expectedSpki.trim() && !SPKI_RE.test(expectedSpki.trim().toLowerCase())) {
      setError(
        "Expected TLS key digest must be 64 hex characters — strip any colons and any 'sha256:' prefix.",
      );
      return;
    }
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
        border: `1px solid ${ui.rule}`,
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
        <Field label="Speaks" htmlFor="df-upstream-kind">
          <select
            id="df-upstream-kind"
            value={upstreamKind}
            onChange={(e) => setUpstreamKind(e.target.value as UpstreamKind)}
          >
            <option value="openapi">An HTTP API described by an OpenAPI document</option>
            <option value="mcp">An MCP server</option>
          </select>
        </Field>
        <Field label="Base URL" htmlFor="df-base-url">
          <input
            id="df-base-url"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            required
            placeholder={upstreamKind === "mcp" ? "http://server.local/mcp" : "http://device.local"}
          />
        </Field>
        {/* An MCP upstream publishes no OpenAPI document, and the gateway refuses the two
            together — so the field is removed rather than disabled. A disabled input still
            reads as "something I could fill in", which is the wrong thing to suggest. */}
        {upstreamKind === "openapi" && (
          <Field label="Spec URL" htmlFor="df-spec-url">
            <input
              id="df-spec-url"
              value={specUrl}
              onChange={(e) => setSpecUrl(e.target.value)}
              placeholder="(auto-discovered if blank)"
            />
          </Field>
        )}
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

        {/* ADR-0015 §8. Create-only, and now for a stronger reason than when it was written:
            the gateway REFUSES this field on an update rather than ignoring it. Supplied at
            registration the digest closes the trust-on-first-use window outright; the same
            value set afterwards is a re-pin, and accepting one here would be the quiet way to
            launder a new key past the pin — no `key_changed` verdict, no quarantine, no record
            that a trust decision was made. Re-pinning has its own approval flow on the device
            detail screen, which is loud and audited. */}
        {!isEdit && (
          <>
            <Field label="Pin TLS key" htmlFor="df-spki">
              <div style={{ display: "grid", gap: 4 }}>
                <input
                  id="df-spki"
                  value={expectedSpki}
                  onChange={(e) => setExpectedSpki(e.target.value)}
                  placeholder="(optional) 64-character hex SHA-256"
                  aria-describedby="df-spki-help"
                  spellCheck={false}
                />
                <span id="df-spki-help" style={{ fontSize: "0.8em", color: ui.muted }}>
                  The device&apos;s public-key digest, obtained out of band. Supplying it here means the
                  gateway never has to trust whatever key it happens to meet first. Only applies to an{" "}
                  <code>https://</code> device, and cannot be set later.
                </span>
              </div>
            </Field>
          </>
        )}

        {/* Editable in BOTH modes, unlike the pin above. This is policy, not evidence: moving
            a device from warn to enforce is an ordinary operation, and while the gateway was
            silently dropping it on a PUT the only way to do it was to delete the device and
            register it again — friction paid to *tighten* a control. Choosing the blank option
            on an edit clears the override and inherits the fleet default, which is a real
            state and not the same as `warn`. */}
        <Field label="On key change" htmlFor="df-fp-policy">
          <select
            id="df-fp-policy"
            value={fingerprintPolicy}
            onChange={(e) => setFingerprintPolicy(e.target.value)}
          >
            <option value="">(use the gateway default)</option>
            <option value="warn">warn — keep dispatching, flag it</option>
            <option value="enforce">enforce — stop dispatching until approved</option>
          </select>
        </Field>
      </div>

      <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center" }}>
        <button type="submit" disabled={submitting}>
          {isEdit ? "Save changes" : "Register"}
        </button>
        <button type="button" onClick={onCancel} disabled={submitting}>
          Cancel
        </button>
        {error && <span style={{ color: health.fail }}>{error}</span>}
      </div>
    </form>
  );
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: React.ReactNode }) {
  return (
    <>
      <label htmlFor={htmlFor} style={{ color: ui.inkSoft, fontSize: 14 }}>
        {label}
      </label>
      {children}
    </>
  );
}
