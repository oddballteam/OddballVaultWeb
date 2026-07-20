import { useEffect, useState } from "react";
import { addMember, listMembers, listMyGroups, removeMemberAndRekey, type GroupMemberSummary } from "../services/groupService";
import type { GroupRow } from "../types/db";
import { isAllowedTenantEmail } from "../utils/tenantEmail";

export function GroupsView({ userId }: { userId: string }) {
  const [groups, setGroups] = useState<GroupRow[]>([]);
  const [selected, setSelected] = useState<GroupRow | null>(null);
  const [members, setMembers] = useState<GroupMemberSummary[]>([]);
  const [newEmail, setNewEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void listMyGroups(userId).then(setGroups);
  }, [userId]);

  async function selectGroup(group: GroupRow) {
    setSelected(group);
    setMembers(await listMembers(group.id));
  }

  const myMembership = members.find((m) => m.userId === userId);
  const isAdmin = myMembership?.role === "admin";

  async function handleAddMember(e: React.FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setError(null);
    if (!isAllowedTenantEmail(newEmail)) {
      setError("Group membership is limited to @oddball.io addresses in this environment.");
      return;
    }
    setBusy(true);
    try {
      await addMember(selected.id, userId, newEmail);
      setNewEmail("");
      setMembers(await listMembers(selected.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add member.");
    } finally {
      setBusy(false);
    }
  }

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

  return (
    <div className="detail-panel">
      <h2>Group Folders</h2>
      <p className="muted">
        New groups are provisioned by an administrator and mapped to an Okta group — see{" "}
        <code>scripts/provisionGroup.ts</code>.
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
          {members.map((m) => (
            <div className="grant-row" key={m.userId}>
              <span>{m.email} <span className="muted">({m.role})</span></span>
              {isAdmin && m.userId !== userId && (
                <button className="danger" disabled={busy} onClick={() => void handleRemoveMember(m.userId)}>
                  Remove
                </button>
              )}
            </div>
          ))}
          {isAdmin && (
            <form onSubmit={(e) => void handleAddMember(e)} style={{ marginTop: "1rem" }}>
              <div className="field-row">
                <label htmlFor="new-member">Add member (email)</label>
                <input id="new-member" type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} required />
              </div>
              {error && <p className="error-text">{error}</p>}
              <button type="submit" disabled={busy}>Add to group</button>
            </form>
          )}
        </div>
      )}
    </div>
  );
}
