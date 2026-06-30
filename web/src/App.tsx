// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api";
import type { Overview, Session } from "./types";
import { Login } from "./components/Login";
import { DeviceList } from "./components/DeviceList";
import { DeviceDetail } from "./components/DeviceDetail";
import { DeviceForm } from "./components/DeviceForm";
import { Dashboard } from "./components/Dashboard";

type FormState = { mode: "create" } | { mode: "edit"; hostname: string };
type View = "devices" | "monitoring";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [view, setView] = useState<View>("devices");
  const [booting, setBooting] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // The UI gates on the gateway's scopes, not a role string (ADR-0007), so password and
  // OIDC sessions are treated uniformly.
  const canWrite = session?.scopes.includes("devices:write") ?? false;

  const refresh = useCallback(async () => {
    try {
      setOverview(await api.overview());
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setSession(null);
      else setError(err instanceof ApiError ? err.message : "Failed to load");
    }
  }, []);

  // Resume an existing session on first load (also how the SSO redirect lands back in).
  useEffect(() => {
    api
      .me()
      .then(setSession)
      .catch(() => setSession(null))
      .finally(() => setBooting(false));
  }, []);

  useEffect(() => {
    if (session) void refresh();
  }, [session, refresh]);

  if (booting) return <p style={{ margin: "10vh auto", textAlign: "center" }}>Loading…</p>;
  if (!session) return <Login onAuthed={setSession} />;

  return (
    <main style={{ maxWidth: 900, margin: "2rem auto", fontFamily: "system-ui, sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <h1>Device MCP Gateway</h1>
        <span>
          <span title={`${session.kind} session`}>{session.name || session.subject}</span>{" "}
          <button
            onClick={async () => {
              const res = await api.logout();
              // For an OIDC session the IdP may hand back a single-logout URL — navigate
              // there so the IdP session ends too (otherwise SSO logs straight back in).
              if (res?.end_session_url) {
                window.location.assign(res.end_session_url);
                return;
              }
              setSession(null);
              setOverview(null);
            }}
          >
            Sign out
          </button>
        </span>
      </header>

      <nav style={{ display: "flex", gap: 8, margin: "8px 0 16px" }}>
        <button onClick={() => setView("devices")} disabled={view === "devices"}>
          Devices
        </button>
        <button onClick={() => setView("monitoring")} disabled={view === "monitoring"}>
          Monitoring
        </button>
      </nav>

      {view === "monitoring" ? (
        <Dashboard />
      ) : (
        <>
          {canWrite &&
            (form ? (
              <DeviceForm
                mode={form.mode}
                hostname={form.mode === "edit" ? form.hostname : undefined}
                onDone={() => {
                  setForm(null);
                  void refresh();
                }}
                onCancel={() => setForm(null)}
              />
            ) : (
              <button onClick={() => setForm({ mode: "create" })}>Register device</button>
            ))}
          {error && <p style={{ color: "crimson" }}>{error}</p>}
          {selected && (
            <DeviceDetail hostname={selected} canWrite={canWrite} onClose={() => setSelected(null)} />
          )}
          {overview ? (
            <DeviceList
              overview={overview}
              canWrite={canWrite}
              onChanged={refresh}
              onSelect={setSelected}
              onEdit={(hostname) => setForm({ mode: "edit", hostname })}
            />
          ) : (
            <p>Loading devices…</p>
          )}
        </>
      )}
    </main>
  );
}
