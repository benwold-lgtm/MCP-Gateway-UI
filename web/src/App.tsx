// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api";
import type { AuthConfig, Overview, Session } from "./types";
import { Login } from "./components/Login";
import { ProviderLogin } from "./components/ProviderLogin";
import { ProviderConsole } from "./components/ProviderConsole";
import { DeviceList } from "./components/DeviceList";
import { DeviceDetail } from "./components/DeviceDetail";
import { DeviceForm } from "./components/DeviceForm";
import { ClaimFromCatalog } from "./components/ClaimFromCatalog";
import { UpgradeOffers } from "./components/UpgradeOffers";
import { Dashboard } from "./components/Dashboard";
import { SupportRequestsInbox } from "./components/SupportRequestsInbox";
import { EnrolmentPanel } from "./components/EnrolmentPanel";
import { BackupPanel } from "./components/BackupPanel";

type FormState = { mode: "create" } | { mode: "edit"; hostname: string } | { mode: "claim" };
type View = "devices" | "monitoring" | "support" | "backup";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [view, setView] = useState<View>("devices");
  const [booting, setBooting] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Which console this deployment IS (ADR-0013 §2/§5). Fetched once at boot rather than by
  // each login component, because the answer also decides which shell a *signed-in* session
  // renders — and the two must not be able to disagree.
  const [config, setConfig] = useState<AuthConfig | null>(null);

  // The UI gates on the gateway's scopes, not a role string (ADR-0007), so password and
  // OIDC sessions are treated uniformly.
  const canWrite = session?.scopes.includes("devices:write") ?? false;
  // A separate scope from `devices:write`, and deliberately read separately: editing a device
  // record and running a tool against the live device are different authorities, and the
  // gateway grants them independently.
  const canInvoke = session?.scopes.includes("tools:call") ?? false;
  // ADR-0017 §7: administering the support-request/grant mechanism itself, gated separately
  // from the tenant-vocabulary scopes above — a session can hold every device scope and
  // still not be trusted to decide who else may act on this fleet.
  const canAdministerSupport = session?.scopes.includes("support:administer") ?? false;
  // The registry is the tenant's own data (ADR-0011), so the tenant console offers backup
  // too — the routes were always mounted on both planes, only the screen was missing.
  // `backup:read` and not the role: a break-glass session's role *is* admin, and it is
  // precisely the session the routes refuse, so gating on the role would offer a screen
  // whose every button 403s. The gateway enforces either way; this only decides what to show.
  const canBackup = session?.scopes.includes("backup:read") ?? false;

  // Provider sessions don't load the overview *here*. A provider session currently has no
  // path to any tenant's fleet at all (ADR-0017 slice 6 removed act-on-tenant; slice 7's
  // replacement hasn't shipped), so polling would just 403 on every tick.
  const isProvider = session?.plane === "provider";

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
    Promise.all([api.me().catch(() => null), api.authConfig().catch(() => null)])
      .then(([me, cfg]) => {
        setSession(me);
        setConfig(cfg);
      })
      .finally(() => setBooting(false));
  }, []);

  useEffect(() => {
    if (session && !isProvider) void refresh();
  }, [session, isProvider, refresh]);

  const signOut = useCallback(async () => {
    const res = await api.logout();
    // For an OIDC session the IdP may hand back a single-logout URL — navigate there so
    // the IdP session ends too (otherwise SSO logs straight back in).
    if (res?.end_session_url) {
      window.location.assign(res.end_session_url);
      return;
    }
    setSession(null);
    setOverview(null);
  }, []);

  if (booting) return <p style={{ margin: "10vh auto", textAlign: "center" }}>Loading…</p>;
  if (!session) {
    // Not a selector — the deployment carries exactly one IdP (`create_app` refuses both),
    // so this reads which console the browser reached rather than offering a choice.
    return config?.provider_enabled ? (
      <ProviderLogin config={config} onAuthed={setSession} />
    ) : (
      <Login onAuthed={setSession} />
    );
  }
  // The plane of the *session* decides the shell, not the deployment: break-glass on a
  // provider console is tenant-plane by construction and belongs in the device console.
  if (isProvider) return <ProviderConsole session={session} onSignOut={signOut} />;

  return (
    <main style={{ maxWidth: 900, margin: "2rem auto", fontFamily: "system-ui, sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <h1>SyncGate</h1>
        <span>
          <span title={`${session.kind} session`}>{session.name || session.subject}</span>{" "}
          <button onClick={signOut}>Sign out</button>
        </span>
      </header>

      <nav style={{ display: "flex", gap: 8, margin: "8px 0 16px" }}>
        <button onClick={() => setView("devices")} disabled={view === "devices"}>
          Devices
        </button>
        <button onClick={() => setView("monitoring")} disabled={view === "monitoring"}>
          Monitoring
        </button>
        {canBackup && (
          <button onClick={() => setView("backup")} disabled={view === "backup"}>
            Backup
          </button>
        )}
        {canAdministerSupport && (
          <button onClick={() => setView("support")} disabled={view === "support"}>
            Support
          </button>
        )}
      </nav>

      {view === "backup" ? (
        <BackupPanel />
      ) : view === "support" ? (
        // Both halves of "this tenant's relationship with its provider" under one tab: the
        // support inbox and the enrolment that makes a provider able to raise a request at
        // all. `support:administer` is the single scope behind both, which is the grouping
        // the gateway chose and the BFF mirrors — a second tab would split one authority
        // across two places for no reason a reader could infer.
        <>
          <SupportRequestsInbox />
          <EnrolmentPanel />
        </>
      ) : view === "monitoring" ? (
        <Dashboard />
      ) : (
        <>
          {canWrite &&
            (form?.mode === "claim" ? (
              <ClaimFromCatalog
                onDone={() => {
                  setForm(null);
                  void refresh();
                }}
                onCancel={() => setForm(null)}
              />
            ) : form ? (
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
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={() => setForm({ mode: "create" })}>Register device</button>
                {/* Only where a catalog estate exists. On lite and plain single-tenant there
                    is no TENANT_ID, so this button used to hand a home user
                    "TENANT_ID not configured on this BFF" from their main onboarding screen.
                    Hidden rather than disabled: a disabled control says "not yet", and for
                    these editions the honest answer is "not a thing here". */}
                {config?.catalog_enabled && (
                  <button onClick={() => setForm({ mode: "claim" })}>Claim from catalog</button>
                )}
              </div>
            ))}
          {error && <p style={{ color: "crimson" }}>{error}</p>}
          {canWrite && <UpgradeOffers />}
          {selected && (
            <DeviceDetail
              hostname={selected}
              canWrite={canWrite}
              canInvoke={canInvoke}
              invokeReason="Running tools needs the 'tools:call' scope, which your role does not carry."
              onClose={() => setSelected(null)}
            />
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
