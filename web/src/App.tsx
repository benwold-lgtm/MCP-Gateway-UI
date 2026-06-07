// SPDX-License-Identifier: Elastic-2.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api";
import type { Overview, Role } from "./types";
import { Login } from "./components/Login";
import { DeviceList } from "./components/DeviceList";
import { RegisterDevice } from "./components/RegisterDevice";

export function App() {
  const [role, setRole] = useState<Role | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [booting, setBooting] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setOverview(await api.overview());
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setRole(null);
      else setError(err instanceof ApiError ? err.message : "Failed to load");
    }
  }, []);

  // Resume an existing session on first load.
  useEffect(() => {
    api
      .me()
      .then(({ role }) => setRole(role))
      .catch(() => setRole(null))
      .finally(() => setBooting(false));
  }, []);

  useEffect(() => {
    if (role) void refresh();
  }, [role, refresh]);

  if (booting) return <p style={{ margin: "10vh auto", textAlign: "center" }}>Loading…</p>;
  if (!role) return <Login onLogin={setRole} />;

  return (
    <main style={{ maxWidth: 900, margin: "2rem auto", fontFamily: "system-ui, sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <h1>Device MCP Gateway</h1>
        <span>
          {role}{" "}
          <button
            onClick={async () => {
              await api.logout();
              setRole(null);
              setOverview(null);
            }}
          >
            Sign out
          </button>
        </span>
      </header>

      {role === "admin" && <RegisterDevice onCreated={refresh} />}
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {overview ? (
        <DeviceList overview={overview} role={role} onChanged={refresh} onSelect={() => {}} />
      ) : (
        <p>Loading devices…</p>
      )}
      <p style={{ marginTop: 24, color: "#888", fontSize: 13 }}>
        Phase 2: monitoring (Prometheus panels) and logs (Loki) via the BFF — see the README.
      </p>
    </main>
  );
}
