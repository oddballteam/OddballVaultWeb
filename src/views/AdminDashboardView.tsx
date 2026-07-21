import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ConfirmDangerModal } from "../components/ConfirmDangerModal";
import { Dropdown } from "../components/Dropdown";
import { listAuditLogs, nukeUserVault } from "../services/adminService";
import {
  createGroupFolder,
  listAllGroups,
  listMembers,
  searchOktaGroups,
  setMemberRole,
  type GroupMemberSummary,
  type OktaGroupSummary,
} from "../services/groupService";
import type { EnterpriseAuditLogRow, GroupRow } from "../types/db";

const OWNER_ROLE_OPTIONS = [
  { value: "member" as const, label: "Editor" },
  { value: "admin" as const, label: "Owner" },
];

export function AdminDashboardView({ userId }: { userId: string }) {
  const [logs, setLogs] = useState<EnterpriseAuditLogRow[]>([]);
  const [search, setSearch] = useState("");
  const [wipeTarget, setWipeTarget] = useState<string | null>(null);
  const [wipeEmail, setWipeEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [groups, setGroups] = useState<GroupRow[]>([]);
  const [expandedGroupId, setExpandedGroupId] = useState<string | null>(null);
  const [groupMembers, setGroupMembers] = useState<GroupMemberSummary[]>([]);
  const [newFolderName, setNewFolderName] = useState("");
  const [oktaGroupQuery, setOktaGroupQuery] = useState("");
  const [oktaGroupResults, setOktaGroupResults] = useState<OktaGroupSummary[]>([]);
  const [selectedOktaGroup, setSelectedOktaGroup] = useState<OktaGroupSummary | null>(null);
  const [groupBusy, setGroupBusy] = useState(false);
  const [groupError, setGroupError] = useState<string | null>(null);

  async function refresh() {
    setLogs(await listAuditLogs());
  }

  async function refreshGroups() {
    setGroups(await listAllGroups());
  }

  useEffect(() => {
    void refresh();
    void refreshGroups();
  }, []);

  useEffect(() => {
    if (selectedOktaGroup) return; // don't re-search right after picking a result
    const handle = setTimeout(() => {
      void searchOktaGroups(oktaGroupQuery)
        .then(setOktaGroupResults)
        .catch(() => setOktaGroupResults([]));
    }, 250);
    return () => clearTimeout(handle);
  }, [oktaGroupQuery, selectedOktaGroup]);

  async function handleCreateFolder(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedOktaGroup) return;
    setGroupError(null);
    setGroupBusy(true);
    try {
      await createGroupFolder(newFolderName, selectedOktaGroup.id, userId);
      setNewFolderName("");
      setOktaGroupQuery("");
      setSelectedOktaGroup(null);
      await refreshGroups();
    } catch (err) {
      setGroupError(err instanceof Error ? err.message : "Failed to create group folder.");
    } finally {
      setGroupBusy(false);
    }
  }

  async function handleExpandGroup(group: GroupRow) {
    if (expandedGroupId === group.id) {
      setExpandedGroupId(null);
      return;
    }
    setExpandedGroupId(group.id);
    setGroupMembers(await listMembers(group.id));
  }

  async function handleRoleChange(memberId: string, role: "member" | "admin") {
    if (!expandedGroupId) return;
    setGroupBusy(true);
    setGroupError(null);
    try {
      await setMemberRole(expandedGroupId, memberId, role, userId);
      setGroupMembers(await listMembers(expandedGroupId));
    } catch (err) {
      setGroupError(err instanceof Error ? err.message : "Failed to change role.");
    } finally {
      setGroupBusy(false);
    }
  }

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

        <div className="card">
          <h2 style={{ marginTop: 0 }}>Group Folders</h2>
          <p className="muted">
            Folder visibility is driven entirely by live Okta group membership — there's no
            manual member list to maintain here. Pick which existing members are folder owners
            (full control) vs. editors (everyone else, capped — can't delete or manage the
            folder).
          </p>

          <form onSubmit={(e) => void handleCreateFolder(e)} style={{ marginBottom: "1rem" }}>
            <div className="field-row">
              <label htmlFor="new-folder-name">Folder name</label>
              <input
                id="new-folder-name"
                value={newFolderName}
                onChange={(e) => setNewFolderName(e.target.value)}
                required
              />
            </div>
            <div className="field-row">
              <label htmlFor="okta-group-search">Okta Group</label>
              <input
                id="okta-group-search"
                value={oktaGroupQuery}
                onChange={(e) => {
                  setOktaGroupQuery(e.target.value);
                  setSelectedOktaGroup(null);
                }}
                placeholder="Search Okta groups by name…"
                autoComplete="off"
                required
              />
              {!selectedOktaGroup && oktaGroupResults.length > 0 && (
                <div className="card" style={{ padding: "0.4rem", marginTop: "0.4rem" }}>
                  {oktaGroupResults.map((g) => (
                    <button
                      type="button"
                      key={g.id}
                      className="secondary"
                      style={{ width: "100%", marginBottom: "0.3rem", textAlign: "left" }}
                      onClick={() => {
                        setSelectedOktaGroup(g);
                        setOktaGroupQuery(g.name);
                        setOktaGroupResults([]);
                      }}
                    >
                      {g.name}
                    </button>
                  ))}
                </div>
              )}
              {selectedOktaGroup && <p className="muted">Selected: {selectedOktaGroup.name}</p>}
            </div>
            {groupError && <p className="error-text">{groupError}</p>}
            <button type="submit" disabled={groupBusy || !selectedOktaGroup}>Create Group Folder</button>
          </form>

          {groups.map((group) => (
            <div key={group.id}>
              <div className="grant-row">
                <span>
                  {group.name} <span className="muted">({group.okta_group_id})</span>
                </span>
                <button className="secondary" onClick={() => void handleExpandGroup(group)}>
                  {expandedGroupId === group.id ? "Hide members" : "View members"}
                </button>
              </div>
              {expandedGroupId === group.id && (
                <div style={{ marginLeft: "1rem", marginBottom: "0.5rem" }}>
                  {groupMembers.length === 0 && (
                    <p className="muted">No synced members yet — an owner needs to view this folder once for it to sync with Okta.</p>
                  )}
                  {groupMembers.map((m) => (
                    <div className="grant-row" key={m.userId}>
                      <span>{m.email}</span>
                      <Dropdown<"member" | "admin">
                        label={m.role === "admin" ? "Owner" : "Editor"}
                        options={OWNER_ROLE_OPTIONS}
                        disabled={groupBusy}
                        onSelect={(role) => void handleRoleChange(m.userId, role)}
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          {groups.length === 0 && <p className="muted">No Group Folders yet.</p>}
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
