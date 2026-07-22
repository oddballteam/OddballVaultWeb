import { Plus } from "lucide-react";
import { useEffect, useState } from "react";
import { ConfirmDangerModal } from "../components/ConfirmDangerModal";
import { Dropdown } from "../components/Dropdown";
import { InfoTooltip } from "../components/InfoTooltip";
import {
  deleteGroupFolder,
  listMembers,
  listMyGroups,
  reconcileGroupMembership,
  renameGroupFolder,
} from "../services/groupService";
import { createItem, listItems } from "../services/vaultService";
import type { GroupRow } from "../types/db";
import { emptyEnvelope, ITEM_TYPE_LABELS, type ItemType, type VaultItem } from "../types/vaultItem";
import { ItemDetailView } from "./ItemDetailView";

const NEW_ITEM_OPTIONS = Object.entries(ITEM_TYPE_LABELS).map(([value, label]) => ({
  value: value as ItemType,
  label,
}));

export function GroupsView({ userId, userEmail }: { userId: string; userEmail: string }) {
  const [groups, setGroups] = useState<GroupRow[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<GroupRow | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void listMyGroups(userId).then(setGroups);
  }, [userId]);

  async function refreshItems(groupId: string) {
    setItems(await listItems(userId, { ownerGroupId: groupId }));
  }

  async function selectGroup(group: GroupRow) {
    setSelectedGroup(group);
    setSelectedItemId(null);
    setRenameValue(group.name);
    setNotice(null);
    setError(null);

    // Membership itself isn't shown here (see AdminDashboardView for that) —
    // this just determines whether the caller can manage the folder, and
    // silently syncs with Okta if they can.
    const members = await listMembers(group.id);
    const mine = members.find((m) => m.userId === userId);
    setIsAdmin(mine?.role === "admin");

    if (mine?.role === "admin") {
      const result = await reconcileGroupMembership(group.id, userId);
      if (!result.ok) setNotice(`Couldn't sync with Okta: ${result.error}.`);
    }

    await refreshItems(group.id);
  }

  async function handleCreateItem(itemType: ItemType) {
    if (!selectedGroup) return;
    const created = await createItem(itemType, emptyEnvelope(`New ${ITEM_TYPE_LABELS[itemType]}`), {
      type: "group",
      groupId: selectedGroup.id,
    });
    await refreshItems(selectedGroup.id);
    setSelectedItemId(created.id);
  }

  async function handleRename(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedGroup || renameValue === selectedGroup.name) return;
    setBusy(true);
    setError(null);
    try {
      await renameGroupFolder(selectedGroup.id, renameValue, userId);
      const renamed = { ...selectedGroup, name: renameValue };
      setSelectedGroup(renamed);
      setGroups((prev) => prev.map((g) => (g.id === renamed.id ? renamed : g)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rename folder.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteConfirmed() {
    if (!selectedGroup) return;
    setBusy(true);
    setError(null);
    try {
      await deleteGroupFolder(selectedGroup.id, userId, selectedGroup.name);
      setGroups((prev) => prev.filter((g) => g.id !== selectedGroup.id));
      setSelectedGroup(null);
      setDeleting(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete folder.");
    } finally {
      setBusy(false);
    }
  }

  const selectedItem = items.find((i) => i.id === selectedItemId) ?? null;

  if (!selectedGroup) {
    return (
      <div className="detail-panel">
        <h2>
          Group Folders
          <InfoTooltip text="Membership is driven entirely by Okta group membership. There's no manual add-member step here. New folders are created by an IT/Sec Admin from the Admin Panel." />
        </h2>
        <div className="card">
          {groups.length === 0 && <p className="muted">You aren't a member of any Group Folders yet.</p>}
          {groups.map((group) => (
            <div className="grant-row" key={group.id}>
              <span>{group.name}</span>
              <button className="secondary" onClick={() => void selectGroup(group)}>Open folder</button>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="main-panels">
      <div className="item-list">
        <button className="secondary" style={{ marginBottom: "0.75rem" }} onClick={() => setSelectedGroup(null)}>
          ← Back to folders
        </button>
        <h3 style={{ marginTop: 0 }}>{selectedGroup.name}</h3>
        <Dropdown<ItemType>
          label="New item"
          icon={<Plus size={16} />}
          options={NEW_ITEM_OPTIONS}
          onSelect={(type) => void handleCreateItem(type)}
        />
        {notice && <p className="muted">{notice}</p>}

        {items.length === 0 && <p className="muted">No records in this folder yet.</p>}
        {items.map((item) => (
          <div
            key={item.id}
            className={`item-card ${item.id === selectedItemId ? "selected" : ""}`}
            onClick={() => setSelectedItemId(item.id)}
          >
            <div className="title">{item.isFavorite ? "★ " : ""}{item.envelope.title}</div>
            <div className="subtitle">{ITEM_TYPE_LABELS[item.itemType]}{item.envelope.username ? ` · ${item.envelope.username}` : ""}</div>
          </div>
        ))}

        {isAdmin && (
          <div className="card" style={{ marginTop: "1rem" }}>
            <h4 style={{ marginTop: 0 }}>Manage folder</h4>
            <form onSubmit={(e) => void handleRename(e)}>
              <div className="field-row">
                <label htmlFor="folder-name">Folder name</label>
                <input
                  id="folder-name"
                  value={renameValue}
                  onChange={(e) => setRenameValue(e.target.value)}
                  required
                />
              </div>
              {error && <p className="error-text">{error}</p>}
              <div className="field-actions">
                <button type="submit" disabled={busy || renameValue === selectedGroup.name}>Save name</button>
                <button type="button" className="danger" disabled={busy} onClick={() => setDeleting(true)}>
                  Delete folder
                </button>
              </div>
            </form>
          </div>
        )}
      </div>

      <div className="detail-panel" style={{ padding: 0 }}>
        {selectedItem ? (
          <ItemDetailView
            item={selectedItem}
            userId={userId}
            userEmail={userEmail}
            onChanged={() => void refreshItems(selectedGroup.id)}
            onDeleted={() => { setSelectedItemId(null); void refreshItems(selectedGroup.id); }}
          />
        ) : (
          <p className="muted" style={{ padding: "1rem" }}>Select a record, or create a new one.</p>
        )}
      </div>

      {deleting && (
        <ConfirmDangerModal
          title="Delete Group Folder"
          message={`This permanently deletes "${selectedGroup.name}" and every item owned by it. This cannot be undone.`}
          confirmPhrase={selectedGroup.name}
          confirmLabel="Delete Folder Permanently"
          busy={busy}
          onConfirm={() => void handleDeleteConfirmed()}
          onCancel={() => setDeleting(false)}
        />
      )}
    </div>
  );
}
