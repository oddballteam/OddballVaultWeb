import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ConfirmDangerModal } from "../components/ConfirmDangerModal";
import { listAuditLogs, nukeUserVault } from "../services/adminService";
import type { EnterpriseAuditLogRow } from "../types/db";

export function AdminDashboardView() {
  const [logs, setLogs] = useState<EnterpriseAuditLogRow[]>([]);
  const [search, setSearch] = useState("");
  const [wipeTarget, setWipeTarget] = useState<string | null>(null);
  const [wipeEmail, setWipeEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setLogs(await listAuditLogs());
  }

  useEffect(() => {
    void refresh();
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    if (!q) return logs;
    return logs.filter(
      (l) =>
        l.actor_email.toLowerCase().includes(q) ||
        l.target_email.toLowerCase().includes(q) ||
        l.item_name.toLowerCase().includes(q) ||
        l.action.toLowerCase().includes(q),
    );
  }, [logs, search]);

  async function handleWipeConfirmed() {
    if (!wipeTarget) return;
    setBusy(true);
    setError(null);
    try {
      const deleted = await nukeUserVault({ email: wipeTarget });
      setStatus(`Deleted ${deleted} item(s) owned by ${wipeTarget}.`);
      setWipeTarget(null);
      setWipeEmail("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to wipe vault.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <div className="topbar">
        <div className="topbar-brand">
          <ShieldAlert size={24} />
          <strong>IT / Security Admin</strong>
        </div>
        <Link to="/" className="admin-link">
          <ArrowLeft size={16} />
          Back to Vault
        </Link>
      </div>

      <div className="detail-panel" style={{ margin: "1rem" }}>
        <div className="card">
          <h2 style={{ marginTop: 0 }}>Audit Log</h2>
          <input
            placeholder="Search by actor, target, item, or action…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ marginBottom: "0.75rem" }}
          />
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Target</th>
                  <th>Item</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log) => (
                  <tr key={log.id}>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                    <td>{log.action}</td>
                    <td>{log.actor_email}</td>
                    <td>{log.target_email}</td>
                    <td>{log.item_name}</td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={5} className="muted">No matching audit entries.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <h2 style={{ marginTop: 0 }}>User Management</h2>
          <p className="muted">
            Permanently deletes every item owned by a user. Does not affect items owned by a Group Folder they
            belong to, or their access grants to other people's shared items.
          </p>
          <div className="field-row">
            <label htmlFor="wipe-email">User email</label>
            <input id="wipe-email" type="email" value={wipeEmail} onChange={(e) => setWipeEmail(e.target.value)} />
          </div>
          {error && <p className="error-text">{error}</p>}
          {status && <p className="muted">{status}</p>}
          <button className="danger" disabled={!wipeEmail} onClick={() => setWipeTarget(wipeEmail)}>
            Wipe User Vault
          </button>
        </div>
      </div>

      {wipeTarget && (
        <ConfirmDangerModal
          title="Wipe User Vault"
          message={`This permanently deletes every item owned by ${wipeTarget}. This cannot be undone.`}
          confirmPhrase={wipeTarget}
          confirmLabel="Wipe Vault Permanently"
          busy={busy}
          onConfirm={() => void handleWipeConfirmed()}
          onCancel={() => setWipeTarget(null)}
        />
      )}
    </div>
  );
}
