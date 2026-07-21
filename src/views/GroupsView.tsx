import { useEffect, useState } from "react";
import { ConfirmDangerModal } from "../components/ConfirmDangerModal";
import {
  deleteGroupFolder,
  listMembers,
  listMyGroups,
  reconcileGroupMembership,
  removeMemberAndRekey,
  renameGroupFolder,
  type GroupMemberSummary,
} from "../services/groupService";
import type { GroupRow } from "../types/db";

export function GroupsView({ userId }: { userId: string }) {
  const [groups, setGroups] = useState<GroupRow[]>([]);
  const [selected, setSelected] = useState<GroupRow | null>(null);
  const [members, setMembers] = useState<GroupMemberSummary[]>([]);
  const [renameValue, setRenameValue] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void listMyGroups(userId).then(setGroups);
  }, [userId]);

  async function selectGroup(group: GroupRow) {
    setSelected(group);
    setRenameValue(group.name);
    setNotice(null);
    setError(null);
    const initialMembers = await listMembers(group.id);
    setMembers(initialMembers);

    const myMembership = initialMembers.find((m) => m.userId === userId);
    if (myMembership?.role === "admin") {
      const result = await reconcileGroupMembership(group.id, userId);
      if (!result.ok) {
        setNotice(`Couldn't sync with Okta: ${result.error}. Membership shown may be stale.`);
      }
      setMembers(await listMembers(group.id));
    }
  }

  const myMembership = members.find((m) => m.userId === userId);
  const isAdmin = myMembership?.role === "admin";

  async function handleRemoveMember(memberId: string) {
    if (!selected) return;
    if (!confirm("Remove this member? This rotates the group's keypair for everyone else.")) return;
    setBusy(true);
    setError(null);
    try {
      await removeMemberAndRekey(selected.id, memberId, userId);
      setMembers(await listMembers(selected.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove member.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRename(e: React.FormEvent) {
    e.preventDefault();
    if (!selected || renameValue === selected.name) return;
    setBusy(true);
    setError(null);
    try {
      await renameGroupFolder(selected.id, renameValue, userId);
      const renamed = { ...selected, name: renameValue };
      setSelected(renamed);
      setGroups((prev) => prev.map((g) => (g.id === renamed.id ? renamed : g)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rename folder.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteConfirmed() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await deleteGroupFolder(selected.id, userId, selected.name);
      setGroups((prev) => prev.filter((g) => g.id !== selected.id));
      setSelected(null);
      setDeleting(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete folder.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="detail-panel">
      <h2>Group Folders</h2>
      <p className="muted">
        Membership is driven entirely by Okta group membership — there's no "add member" step
        here. New folders are created by an IT/Sec Admin from the Admin Panel.
      </p>
      <div className="card">
        {groups.length === 0 && <p className="muted">You aren't a member of any Group Folders yet.</p>}
        {groups.map((group) => (
          <div className="grant-row" key={group.id}>
            <span>{group.name}</span>
            <button className="secondary" onClick={() => void selectGroup(group)}>View members</button>
          </div>
        ))}
      </div>

      {selected && (
        <div className="card">
          <h3>{selected.name} members</h3>
          {notice && <p className="muted">{notice}</p>}
          {members.map((m) => (
            <div className="grant-row" key={m.userId}>
              <span>{m.email} <span className="muted">({m.role === "admin" ? "owner" : "editor"})</span></span>
              {isAdmin && m.userId !== userId && (
                <button className="danger" disabled={busy} onClick={() => void handleRemoveMember(m.userId)}>
                  Remove
                </button>
              )}
            </div>
          ))}

          {error && <p className="error-text">{error}</p>}

          {isAdmin && (
            <>
              <form onSubmit={(e) => void handleRename(e)} style={{ marginTop: "1rem" }}>
                <div className="field-row">
                  <label htmlFor="folder-name">Folder name</label>
                  <input
                    id="folder-name"
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    required
                  />
                </div>
                <div className="field-actions">
                  <button type="submit" disabled={busy || renameValue === selected.name}>Save name</button>
                  <button type="button" className="danger" disabled={busy} onClick={() => setDeleting(true)}>
                    Delete folder
                  </button>
                </div>
              </form>
            </>
          )}
        </div>
      )}

      {deleting && selected && (
        <ConfirmDangerModal
          title="Delete Group Folder"
          message={`This permanently deletes "${selected.name}" and every item owned by it. This cannot be undone.`}
          confirmPhrase={selected.name}
          confirmLabel="Delete Folder Permanently"
          busy={busy}
          onConfirm={() => void handleDeleteConfirmed()}
          onCancel={() => setDeleting(false)}
        />
      )}
    </div>
  );
}
