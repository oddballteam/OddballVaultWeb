import { useEffect, useState } from "react";
import { AttachmentsPanel } from "../components/AttachmentsPanel";
import { PasswordField } from "../components/PasswordField";
import { ShareDialog } from "../components/ShareDialog";
import { TotpWidget } from "../components/TotpWidget";
import { hardDelete, softDelete, toggleFavorite, updateItem } from "../services/vaultService";
import { ROLE_LABELS, type ItemEnvelope, type ItemType, type VaultItem } from "../types/vaultItem";

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

  useEffect(() => {
    setEnvelope(item.envelope);
    setDirty(false);
  }, [item.id, item.envelope]);

  const canEdit = item.myRole === "owner" || item.myRole === "edit_share" || item.myRole === "edit";
  const canManageSharing = item.myRole === "owner" || item.myRole === "edit_share";

  function setField(key: keyof ItemEnvelope, value: string) {
    setEnvelope((prev) => ({ ...prev, [key]: value }));
    setDirty(true);
  }

  async function handleSave() {
    setSaving(true);
    try {
      await updateItem(item.id, envelope, userId);
      setDirty(false);
      onChanged();
    } finally {
      setSaving(false);
    }
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

  const fields = FIELDS_BY_TYPE[item.itemType];

  return (
    <div className="detail-panel">
      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "0.5rem" }}>
        <div className="field-row" style={{ flex: 1, minWidth: "200px" }}>
          <input
            value={envelope.title}
            onChange={(e) => setField("title", e.target.value)}
            readOnly={!canEdit}
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
          <button className="danger" onClick={() => void handleDelete()}>
            {item.isDeleted ? "Delete permanently" : "Move to trash"}
          </button>
        </div>
      </div>

      <span className="muted">Your role: {ROLE_LABELS[item.myRole]}</span>

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
              onChange={canEdit ? (v) => setField(field.key, v) : undefined}
              readOnly={!canEdit}
              allowGenerate={field.allowGenerate}
            />
          ) : (
            <div className="field-row" key={field.key}>
              <label>{field.label}</label>
              <input
                value={(envelope[field.key] as string) ?? ""}
                onChange={(e) => setField(field.key, e.target.value)}
                readOnly={!canEdit}
              />
            </div>
          ),
        )}

        {item.itemType === "login" && envelope.totpSecret && <TotpWidget secret={envelope.totpSecret} />}

        <PasswordField
          label="Notes"
          value={envelope.notes ?? ""}
          onChange={canEdit ? (v) => setField("notes", v) : undefined}
          readOnly={!canEdit}
          multiline
        />
        <div className="field-row">
          <label>Tags (comma-separated)</label>
          <input
            value={envelope.tags.join(", ")}
            onChange={(e) => {
              setEnvelope((prev) => ({ ...prev, tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) }));
              setDirty(true);
            }}
            readOnly={!canEdit}
          />
        </div>

        {canEdit && (
          <button disabled={!dirty || saving} onClick={() => void handleSave()}>
            {saving ? "Saving…" : "Save changes"}
          </button>
        )}
      </div>

      <AttachmentsPanel itemId={item.id} userId={userId} canEdit={canEdit} />
    </div>
  );
}
