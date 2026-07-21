import { Eye, EyeOff, FolderInput, Pencil, Plus, Save, Trash2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { AttachmentsPanel } from "../components/AttachmentsPanel";
import { Dropdown } from "../components/Dropdown";
import { PasswordField } from "../components/PasswordField";
import { ShareDialog } from "../components/ShareDialog";
import { TotpWidget } from "../components/TotpWidget";
import { listMyGroups } from "../services/groupService";
import { moveItemToGroup } from "../services/sharingService";
import { hardDelete, softDelete, toggleFavorite, updateItem } from "../services/vaultService";
import type { GroupRow } from "../types/db";
import { ROLE_LABELS, type CustomField, type ItemEnvelope, type ItemType, type VaultItem } from "../types/vaultItem";

const MAX_CUSTOM_FIELDS = 5;
const CLIPBOARD_CLEAR_MS = 30_000;

async function copyWithAutoClear(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  setTimeout(() => {
    navigator.clipboard.writeText("").catch(() => undefined);
  }, CLIPBOARD_CLEAR_MS);
}

type FieldConfig = { key: keyof ItemEnvelope; label: string; sensitive?: boolean; allowGenerate?: boolean };

const FIELDS_BY_TYPE: Record<ItemType, FieldConfig[]> = {
  login: [
    { key: "username", label: "Username" },
    { key: "password", label: "Password", sensitive: true, allowGenerate: true },
    { key: "url", label: "URL" },
    { key: "totpSecret", label: "TOTP secret", sensitive: true },
  ],
  note: [],
  card: [
    { key: "cardholderName", label: "Cardholder name" },
    { key: "cardNumber", label: "Card number", sensitive: true },
    { key: "cardExpiry", label: "Expiry (MM/YY)" },
    { key: "cardCvv", label: "CVV", sensitive: true },
    { key: "cardPin", label: "PIN", sensitive: true },
  ],
  identity: [
    { key: "fullName", label: "Full name" },
    { key: "email", label: "Email" },
    { key: "phone", label: "Phone" },
    { key: "addressLine1", label: "Address line 1" },
    { key: "addressLine2", label: "Address line 2" },
    { key: "city", label: "City" },
    { key: "state", label: "State" },
    { key: "postalCode", label: "Postal code" },
    { key: "country", label: "Country" },
  ],
  ssh_key: [
    { key: "sshHost", label: "Host" },
    { key: "sshPublicKey", label: "Public key" },
    { key: "sshPrivateKey", label: "Private key", sensitive: true },
  ],
  api_credential: [
    { key: "serviceName", label: "Service name" },
    { key: "keyName", label: "Key name" },
    { key: "keyValue", label: "Key value", sensitive: true },
    { key: "endpoint", label: "Endpoint" },
  ],
};

export function ItemDetailView({
  item,
  userId,
  userEmail,
  onChanged,
  onDeleted,
}: {
  item: VaultItem;
  userId: string;
  userEmail: string;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const [envelope, setEnvelope] = useState<ItemEnvelope>(item.envelope);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [revealedCustomFields, setRevealedCustomFields] = useState<Set<number>>(new Set());
  const [myGroups, setMyGroups] = useState<GroupRow[]>([]);
  const [moveError, setMoveError] = useState<string | null>(null);
  const [moving, setMoving] = useState(false);

  useEffect(() => {
    setEnvelope(item.envelope);
    setDirty(false);
    setIsEditing(false);
    setRevealedCustomFields(new Set());
    setMoveError(null);
  }, [item.id, item.envelope]);

  useEffect(() => {
    void listMyGroups(userId).then(setMyGroups);
  }, [userId]);

  const canEdit = item.myRole === "owner" || item.myRole === "edit_share" || item.myRole === "edit";
  const canManageSharing = item.myRole === "owner" || item.myRole === "edit_share";
  const canMoveToFolder = item.myRole === "owner" && !item.ownerGroupId && myGroups.length > 0;
  const editable = canEdit && isEditing;

  function setField(key: keyof ItemEnvelope, value: string) {
    setEnvelope((prev) => ({ ...prev, [key]: value }));
    setDirty(true);
  }

  function setCustomField(index: number, patch: Partial<CustomField>) {
    setEnvelope((prev) => {
      const customFields = [...prev.customFields];
      customFields[index] = { ...customFields[index], ...patch };
      return { ...prev, customFields };
    });
    setDirty(true);
  }

  function addCustomField() {
    if (envelope.customFields.length >= MAX_CUSTOM_FIELDS) return;
    setEnvelope((prev) => ({
      ...prev,
      customFields: [...prev.customFields, { label: "", value: "", isSensitive: false }],
    }));
    setDirty(true);
  }

  function removeCustomField(index: number) {
    setEnvelope((prev) => ({ ...prev, customFields: prev.customFields.filter((_, i) => i !== index) }));
    setDirty(true);
  }

  function toggleRevealCustomField(index: number) {
    setRevealedCustomFields((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  async function handleSave() {
    setSaving(true);
    try {
      await updateItem(item.id, envelope, userId);
      setDirty(false);
      setIsEditing(false);
      onChanged();
    } finally {
      setSaving(false);
    }
  }

  function handleCancelEdit() {
    setEnvelope(item.envelope);
    setDirty(false);
    setIsEditing(false);
  }

  async function handleFavorite() {
    await toggleFavorite(item.id, !item.isFavorite);
    onChanged();
  }

  async function handleDelete() {
    if (item.isDeleted) {
      if (confirm("Permanently delete this item? This cannot be undone.")) {
        await hardDelete(item.id);
        onDeleted();
      }
    } else {
      await softDelete(item.id, userId);
      onChanged();
    }
  }

  async function handleMoveToGroup(groupId: string) {
    setMoveError(null);
    setMoving(true);
    try {
      await moveItemToGroup(item.id, userId, groupId);
      onChanged();
    } catch (err) {
      setMoveError(err instanceof Error ? err.message : "Failed to move item.");
    } finally {
      setMoving(false);
    }
  }

  const fields = FIELDS_BY_TYPE[item.itemType].filter((field) => isEditing || Boolean(envelope[field.key]));
  const hasNotes = isEditing || Boolean(envelope.notes);
  const hasTags = isEditing || envelope.tags.length > 0;

  return (
    <div className="detail-panel">
      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "0.5rem" }}>
        <div className="field-row" style={{ flex: 1, minWidth: "200px", marginBottom: 0 }}>
          <input
            value={envelope.title}
            onChange={(e) => setField("title", e.target.value)}
            readOnly={!editable}
            style={{ fontSize: "1.3rem", fontWeight: 600 }}
          />
        </div>
        <div className="field-actions">
          <button className="secondary" onClick={() => void handleFavorite()}>
            {item.isFavorite ? "★ Favorited" : "☆ Favorite"}
          </button>
          {canManageSharing && (
            <button className="secondary" onClick={() => setSharing((s) => !s)}>Share</button>
          )}
          {canMoveToFolder && (
            <Dropdown<string>
              label="Move to folder"
              icon={<FolderInput size={16} />}
              options={myGroups.map((g) => ({ value: g.id, label: g.name }))}
              disabled={moving}
              onSelect={(groupId) => void handleMoveToGroup(groupId)}
            />
          )}
          {canEdit && !isEditing && (
            <button className="icon-button" title="Edit" aria-label="Edit" onClick={() => setIsEditing(true)}>
              <Pencil size={18} />
            </button>
          )}
          {canEdit && isEditing && (
            <>
              <button className="icon-button" title="Cancel" aria-label="Cancel" onClick={handleCancelEdit} disabled={saving}>
                <X size={18} />
              </button>
              <button
                className="icon-button"
                title="Save"
                aria-label="Save"
                disabled={!dirty || saving}
                onClick={() => void handleSave()}
              >
                <Save size={18} />
              </button>
            </>
          )}
          <button className="danger" onClick={() => void handleDelete()}>
            {item.isDeleted ? "Delete permanently" : "Move to trash"}
          </button>
        </div>
      </div>

      <span className="muted">Your role: {ROLE_LABELS[item.myRole]}</span>
      {moveError && <p className="error-text">{moveError}</p>}

      {sharing && (
        <ShareDialog
          itemId={item.id}
          userId={userId}
          userEmail={userEmail}
          canManage={canManageSharing}
          isOwner={item.myRole === "owner"}
          onClose={() => setSharing(false)}
          onChanged={onChanged}
        />
      )}

      <div className="card">
        {fields.map((field) =>
          field.sensitive ? (
            <PasswordField
              key={field.key}
              label={field.label}
              value={(envelope[field.key] as string) ?? ""}
              onChange={editable ? (v) => setField(field.key, v) : undefined}
              readOnly={!editable}
              allowGenerate={field.allowGenerate}
            />
          ) : (
            <div className="field-row" key={field.key}>
              <label>{field.label}</label>
              <input
                value={(envelope[field.key] as string) ?? ""}
                onChange={(e) => setField(field.key, e.target.value)}
                readOnly={!editable}
              />
            </div>
          ),
        )}

        {item.itemType === "login" && envelope.totpSecret && <TotpWidget secret={envelope.totpSecret} />}

        {hasNotes && (
          <PasswordField
            label="Notes"
            value={envelope.notes ?? ""}
            onChange={editable ? (v) => setField("notes", v) : undefined}
            readOnly={!editable}
            multiline
          />
        )}
        {hasTags && (
          <div className="field-row">
            <label>Tags (comma-separated)</label>
            <input
              value={envelope.tags.join(", ")}
              onChange={(e) => {
                setEnvelope((prev) => ({ ...prev, tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) }));
                setDirty(true);
              }}
              readOnly={!editable}
            />
          </div>
        )}

        {envelope.customFields
          .map((field, index) => ({ field, index }))
          .filter(({ field }) => isEditing || field.value)
          .map(({ field, index }) =>
            isEditing ? (
              <div className="field-row" key={index}>
                <input
                  value={field.label}
                  onChange={(e) => setCustomField(index, { label: e.target.value })}
                  placeholder="Field name"
                  style={{ marginBottom: "0.4rem" }}
                />
                <input
                  type={field.isSensitive && !revealedCustomFields.has(index) ? "password" : "text"}
                  value={field.value}
                  onChange={(e) => setCustomField(index, { value: e.target.value })}
                />
                <div className="field-actions" style={{ marginTop: "0.4rem" }}>
                  {field.isSensitive && (
                    <button type="button" className="secondary" onClick={() => toggleRevealCustomField(index)}>
                      {revealedCustomFields.has(index) ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  )}
                  <button type="button" className="secondary" onClick={() => void copyWithAutoClear(field.value)}>
                    Copy
                  </button>
                  <button
                    type="button"
                    className={field.isSensitive ? "" : "secondary"}
                    onClick={() => setCustomField(index, { isSensitive: !field.isSensitive })}
                  >
                    Sensitive
                  </button>
                  <button
                    type="button"
                    className="icon-button"
                    title="Remove field"
                    aria-label="Remove field"
                    onClick={() => removeCustomField(index)}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ) : field.isSensitive ? (
              <PasswordField key={index} label={field.label} value={field.value} readOnly />
            ) : (
              <div className="field-row" key={index}>
                <label>{field.label}</label>
                <input value={field.value} readOnly />
              </div>
            ),
          )}
        {isEditing && envelope.customFields.length < MAX_CUSTOM_FIELDS && (
          <button type="button" className="secondary" onClick={addCustomField}>
            <Plus size={16} /> Add field
          </button>
        )}
      </div>

      <AttachmentsPanel itemId={item.id} userId={userId} canEdit={canEdit} />
    </div>
  );
}
