// SPDX-License-Identifier: Elastic-2.0
import { useState } from "react";
import { api, ApiError } from "../api";

// Admin-only mini form. Kept intentionally small — extend with auth/transport/
// rate-limit fields as the gateway's POST /devices payload grows.
export function RegisterDevice({ onCreated }: { onCreated: () => void }) {
  const [hostname, setHostname] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.registerDevice({ hostname, base_url: baseUrl });
      setHostname("");
      setBaseUrl("");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to register");
    }
  }

  return (
    <form onSubmit={submit} style={{ display: "flex", gap: 8, margin: "12px 0", flexWrap: "wrap" }}>
      <input placeholder="hostname" value={hostname} onChange={(e) => setHostname(e.target.value)} />
      <input
        placeholder="base_url (http://...)"
        value={baseUrl}
        onChange={(e) => setBaseUrl(e.target.value)}
        size={32}
      />
      <button type="submit">Register device</button>
      {error && <span style={{ color: "crimson" }}>{error}</span>}
    </form>
  );
}
