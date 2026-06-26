// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { DeadLetterList, Role } from "../types";

// Per-device dead-letter queue (gateway F-10). Inspect is a read (any session);
// replay/drain mutate and are admin-only. The gateway returns 400 in embedded mode
// (no in-process DLQ), which we render as "distributed mode only".
export function DeadLetterPanel({ hostname, role }: { hostname: string; role: Role }) {
  const [list, setList] = useState<DeadLetterList | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isAdmin = role === "admin";

  const load = useCallback(async () => {
    setError(null);
    try {
      setList(await api.deadLetters(hostname));
      setUnavailable(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) setUnavailable(true);
      else setError(err instanceof ApiError ? err.message : "Failed to load dead-letter queue");
    }
  }, [hostname]);

  useEffect(() => {
    setList(null);
    setNotice(null);
    void load();
  }, [load]);

  async function replay(ids?: string[]) {
    setBusy(true);
    setNotice(null);
    try {
      const { replayed } = await api.replayDeadLetters(hostname, ids);
      setNotice(`Replayed ${replayed}.`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Replay failed");
    } finally {
      setBusy(false);
    }
  }

  async function drain(ids?: string[]) {
    const ok = confirm(
      ids ? "Drop this dead-lettered call?" : `Drain the entire dead-letter queue for ${hostname}?`,
    );
    if (!ok) return;
    setBusy(true);
    setNotice(null);
    try {
      const { removed } = await api.drainDeadLetters(hostname, ids);
      setNotice(`Drained ${removed}.`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Drain failed");
    } finally {
      setBusy(false);
    }
  }

  if (unavailable) {
    return (
      <div style={{ marginTop: 16 }}>
        <h3>Dead-letter queue</h3>
        <p style={{ color: "#888", fontSize: 13 }}>Available in distributed mode only.</p>
      </div>
    );
  }

  return (
    <div style={{ marginTop: 16 }}>
      <h3 style={{ marginBottom: 4 }}>Dead-letter queue {list ? `(${list.count})` : ""}</h3>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {notice && <p style={{ color: "#2a7", fontSize: 13 }}>{notice}</p>}
      {!list && !error && <p>Loading…</p>}
      {list && list.entries.length === 0 && <p style={{ color: "#888", fontSize: 13 }}>Empty.</p>}
      {list && list.entries.length > 0 && (
        <>
          {isAdmin && (
            <div style={{ display: "flex", gap: 8, margin: "4px 0 8px" }}>
              <button onClick={() => replay()} disabled={busy}>
                Replay all
              </button>
              <button onClick={() => drain()} disabled={busy}>
                Drain all
              </button>
            </div>
          )}
          <table cellPadding={6} style={{ borderCollapse: "collapse", width: "100%", fontSize: 13 }}>
            <thead>
              <tr>
                <th align="left">Method</th>
                <th align="left">Reason</th>
                <th align="left">When</th>
                <th align="left">Request</th>
                {isAdmin && <th></th>}
              </tr>
            </thead>
            <tbody>
              {list.entries.map((e) => (
                <tr key={e.id} style={{ borderTop: "1px solid #eee" }}>
                  <td>
                    <code>{e.method ?? "—"}</code>
                  </td>
                  <td>{e.reason || "—"}</td>
                  <td title={e.ts}>{fmtTs(e.ts)}</td>
                  <td>
                    <code style={{ color: "#888" }}>{e.request_id || e.rid || e.id}</code>
                  </td>
                  {isAdmin && (
                    <td align="right" style={{ whiteSpace: "nowrap" }}>
                      <button onClick={() => replay([e.id])} disabled={busy}>
                        Replay
                      </button>{" "}
                      <button onClick={() => drain([e.id])} disabled={busy}>
                        Drain
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function fmtTs(ts: string): string {
  if (!ts) return "—";
  const n = Number(ts);
  if (Number.isFinite(n) && n > 0) {
    const ms = n > 1e12 ? n : n * 1000; // epoch seconds → ms (heuristic); falls back to raw
    return new Date(ms).toLocaleString();
  }
  return ts;
}
