import { useEffect, useState } from "react";
import {
  changeRole,
  listGrants,
  revokeAccess,
  searchDirectoryEmails,
  shareItemWithUser,
  transferOwnership,
  type GrantSummary,
} from "../services/sharingService";
import { ROLE_LABELS, type ItemRole } from "../types/vaultItem";
import { isAllowedTenantEmail } from "../utils/tenantEmail";
import { Dropdown } from "./Dropdown";

const SHAREABLE_ROLES: Exclude<ItemRole, "owner">[] = ["view", "edit", "edit_share"];
const SHAREABLE_ROLE_OPTIONS = SHAREABLE_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }));

export function ShareDialog({
  itemId,
  userId,
  userEmail,
  canManage,
  isOwner,
  onClose,
  onChanged,
}: {
  itemId: string;
  userId: string;
  userEmail: string;
  canManage: boolean;
  isOwner: boolean;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const [grants, setGrants] = useState<GrantSummary[]>([]);
  const [email, setEmail] = useState("");
  const [emailSuggestions, setEmailSuggestions] = useState<string[]>([]);
  const [role, setRole] = useState<Exclude<ItemRole, "owner">>("view");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setGrants(await listGrants(itemId));
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [itemId]);

  useEffect(() => {
    const handle = setTimeout(() => {
      void searchDirectoryEmails(email)
        .then(setEmailSuggestions)
        .catch(() => setEmailSuggestions([]));
    }, 200);
    return () => clearTimeout(handle);
  }, [email]);

  async function handleShare(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!isAllowedTenantEmail(email)) {
      setError("Sharing is limited to @oddball.io addresses in this environment.");
      return;
    }
    setBusy(true);
    try {
      await shareItemWithUser(itemId, userId, userEmail, email, role);
      setEmail("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to share item.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke(grant: GrantSummary) {
    setBusy(true);
    setError(null);
    try {
      await revokeAccess(itemId, grant.granteeType, grant.granteeId, userId);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke access.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRoleChange(grant: GrantSummary, newRole: Exclude<ItemRole, "owner">) {
    setBusy(true);
    try {
      await changeRole(itemId, grant.granteeType, grant.granteeId, newRole, userId);
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function handleTransferOwnership(grant: GrantSummary) {
    if (!confirm(`Make ${grant.displayName} the owner of this item? You'll be moved to Edit & Share.`)) return;
    setBusy(true);
    setError(null);
    try {
      await transferOwnership(itemId, userId, userEmail, grant.granteeType, grant.granteeId);
      await refresh();
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to transfer ownership.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <h3>Sharing</h3>
        <button className="secondary" onClick={onClose}>Close</button>
      </div>

      {grants.map((grant) => (
        <div className="grant-row" key={`${grant.granteeType}:${grant.granteeId}`}>
          <span>
            {grant.displayName} <span className="muted">({grant.granteeType})</span>
          </span>
          {grant.role === "owner" ? (
            <span className="muted">{ROLE_LABELS.owner}</span>
          ) : canManage ? (
            <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <Dropdown<Exclude<ItemRole, "owner">>
                label={ROLE_LABELS[grant.role]}
                options={SHAREABLE_ROLE_OPTIONS}
                disabled={busy}
                onSelect={(newRole) => void handleRoleChange(grant, newRole)}
              />
              {isOwner && (
                <button className="secondary" disabled={busy} onClick={() => void handleTransferOwnership(grant)}>
                  Transfer Ownership
                </button>
              )}
              <button className="danger" disabled={busy} onClick={() => void handleRevoke(grant)}>Revoke</button>
            </div>
          ) : (
            <span className="muted">{ROLE_LABELS[grant.role]}</span>
          )}
        </div>
      ))}

      {canManage && (
        <form onSubmit={(e) => void handleShare(e)} style={{ marginTop: "1rem" }}>
          <div className="field-row">
            <label htmlFor="share-email">Share with (email)</label>
            <input
              id="share-email"
              type="email"
              list="share-email-suggestions"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <datalist id="share-email-suggestions">
              {emailSuggestions.map((suggestion) => (
                <option key={suggestion} value={suggestion} />
              ))}
            </datalist>
          </div>
          <div className="field-row">
            <label>Role</label>
            <Dropdown<Exclude<ItemRole, "owner">>
              label={ROLE_LABELS[role]}
              options={SHAREABLE_ROLE_OPTIONS}
              onSelect={setRole}
            />
          </div>
          {error && <p className="error-text">{error}</p>}
          <button type="submit" disabled={busy}>Share</button>
        </form>
      )}
    </div>
  );
}
