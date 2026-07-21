/**
 * Grant, re-role, and revoke item access. Revocation performs a real
 * cryptographic rotation (new Item Key, re-encrypted content and
 * attachments, re-wrapped for every remaining grantee) — deleting the
 * grant row alone would only remove the DB-visible ACL entry, not stop
 * someone who already cached the old key from continuing to read it.
 */
import { supabase } from "../api/supabase";
import { decryptEnvelope, encryptEnvelope } from "../crypto/envelope";
import { generateAesKeyBytes, importAesKey } from "../crypto/aes";
import { importPublicKey, wrapKey } from "../crypto/rsa";
import type { ItemKeyRow, ItemRow } from "../types/db";
import type { ItemRole } from "../types/vaultItem";
import { isAllowedTenantEmail } from "../utils/tenantEmail";
import { resolveItemKey, resolveItemKeyRaw } from "./access";
import { reencryptAttachmentsForRotation } from "./attachmentService";
import { logEnterpriseAuditEvent, logEvent } from "./auditService";

export interface GrantSummary {
  granteeType: "user" | "group";
  granteeId: string;
  displayName: string; // email for users, group name for groups
  role: ItemRole;
}

export async function listGrants(itemId: string): Promise<GrantSummary[]> {
  const { data, error } = await supabase.from("item_keys").select("*").eq("item_id", itemId);
  if (error) throw error;
  const rows = (data as ItemKeyRow[]) ?? [];

  return Promise.all(
    rows.map(async (row) => {
      const displayName =
        row.grantee_type === "user"
          ? ((await supabase.from("user_directory").select("email").eq("id", row.grantee_id).single()).data
              ?.email ?? row.grantee_id)
          : ((await supabase.from("groups").select("name").eq("id", row.grantee_id).single()).data?.name ??
              row.grantee_id);
      return { granteeType: row.grantee_type, granteeId: row.grantee_id, displayName, role: row.role as ItemRole };
    }),
  );
}

/** Prefix search for the "Share with" autocomplete — user_directory is readable by any authenticated user (see 0002_users.sql). */
export async function searchDirectoryEmails(prefix: string): Promise<string[]> {
  const trimmed = prefix.trim();
  if (trimmed.length < 2) return [];
  const { data, error } = await supabase.from("user_directory").select("email").ilike("email", `${trimmed}%`).limit(10);
  if (error) throw error;
  return data.map((row) => row.email as string);
}

export async function shareItemWithUser(
  itemId: string,
  actorUserId: string,
  actorEmail: string,
  recipientEmail: string,
  role: Exclude<ItemRole, "owner">,
): Promise<void> {
  if (!isAllowedTenantEmail(recipientEmail)) {
    throw new Error("Sharing is limited to @oddball.io addresses in this environment.");
  }

  const { data: recipient, error: lookupError } = await supabase
    .from("user_directory")
    .select("id, public_key")
    .eq("email", recipientEmail)
    .single();
  if (lookupError) throw new Error(`No user found with email ${recipientEmail}.`);

  const { data: item, error: itemError } = await supabase
    .from("items")
    .select("key_version, nonce, ciphertext")
    .eq("id", itemId)
    .single();
  if (itemError) throw itemError;

  const rawItemKey = await resolveItemKeyRaw(itemId, actorUserId);
  const recipientPublicKey = await importPublicKey(recipient.public_key);
  const wrappedItemKey = await wrapKey(rawItemKey, recipientPublicKey);

  const { error: insertError } = await supabase.from("item_keys").insert({
    item_id: itemId,
    grantee_type: "user",
    grantee_id: recipient.id,
    wrapped_item_key: wrappedItemKey,
    role,
    key_version: (item as Pick<ItemRow, "key_version">).key_version,
    granted_by: actorUserId,
  });
  if (insertError) throw insertError;

  await logEvent(actorUserId, "item_shared", { itemId, detail: `Shared with ${recipientEmail} as ${role}` });

  const itemKey = await importAesKey(rawItemKey);
  const envelope = await decryptEnvelope(itemKey, item.nonce, item.ciphertext);
  await logEnterpriseAuditEvent("item_shared", actorEmail, recipientEmail, envelope.title);
}

export async function changeRole(
  itemId: string,
  granteeType: "user" | "group",
  granteeId: string,
  newRole: Exclude<ItemRole, "owner">,
  actorUserId: string,
): Promise<void> {
  const { error } = await supabase
    .from("item_keys")
    .update({ role: newRole })
    .eq("item_id", itemId)
    .eq("grantee_type", granteeType)
    .eq("grantee_id", granteeId);
  if (error) throw error;
  await logEvent(actorUserId, "role_changed", { itemId, detail: `${granteeType}:${granteeId} -> ${newRole}` });
}

/**
 * Removes a grant AND rotates the item's key so the revoked grantee's
 * cached copy stops being useful. This is the expensive-but-correct path —
 * see the module docstring.
 */
export async function revokeAccess(
  itemId: string,
  granteeType: "user" | "group",
  granteeId: string,
  actorUserId: string,
): Promise<void> {
  const { data: itemRow, error: itemError } = await supabase.from("items").select("*").eq("id", itemId).single();
  if (itemError) throw itemError;
  const item = itemRow as ItemRow;

  const oldItemKey = await resolveItemKey(itemId, actorUserId);
  const envelope = await decryptEnvelope(oldItemKey, item.nonce, item.ciphertext);

  const { data: grantRows, error: grantsError } = await supabase.from("item_keys").select("*").eq("item_id", itemId);
  if (grantsError) throw grantsError;
  const remainingGrants = ((grantRows as ItemKeyRow[]) ?? []).filter(
    (g) => !(g.grantee_type === granteeType && g.grantee_id === granteeId),
  );
  if (remainingGrants.length === 0) {
    throw new Error("Cannot revoke the last remaining grant on an item — delete the item instead.");
  }

  const newItemKeyBytes = generateAesKeyBytes();
  const newItemKey = await importAesKey(newItemKeyBytes);
  const { nonce, ciphertext } = await encryptEnvelope(newItemKey, envelope);
  const newKeyVersion = item.key_version + 1;

  await reencryptAttachmentsForRotation(itemId, oldItemKey, newItemKey);

  const { error: updateError } = await supabase
    .from("items")
    .update({ nonce, ciphertext, key_version: newKeyVersion, updated_at: new Date().toISOString() })
    .eq("id", itemId);
  if (updateError) throw updateError;

  for (const grant of remainingGrants) {
    const publicKeySpki =
      grant.grantee_type === "user"
        ? (await supabase.from("user_directory").select("public_key").eq("id", grant.grantee_id).single()).data
            ?.public_key
        : (await supabase.from("groups").select("public_key").eq("id", grant.grantee_id).single()).data?.public_key;
    if (!publicKeySpki) continue;

    const publicKey = await importPublicKey(publicKeySpki);
    const wrappedItemKey = await wrapKey(newItemKeyBytes, publicKey);

    const { error: reinsertError } = await supabase.from("item_keys").insert({
      item_id: itemId,
      grantee_type: grant.grantee_type,
      grantee_id: grant.grantee_id,
      wrapped_item_key: wrappedItemKey,
      role: grant.role,
      key_version: newKeyVersion,
      granted_by: grant.granted_by,
    });
    if (reinsertError) throw reinsertError;
  }

  const { error: deleteOldError } = await supabase
    .from("item_keys")
    .delete()
    .eq("item_id", itemId)
    .lt("key_version", newKeyVersion);
  if (deleteOldError) throw deleteOldError;

  await logEvent(actorUserId, "item_key_rotated", {
    itemId,
    detail: `Revoked ${granteeType}:${granteeId}, rotated to key_version ${newKeyVersion}`,
  });
  await logEvent(actorUserId, "item_unshared", { itemId, detail: `${granteeType}:${granteeId}` });
}

/**
 * Demotes whichever grant currently holds "owner" to "edit_share" (so they
 * keep access, just not ownership) and promotes the target grantee to
 * "owner". No key rotation needed — every existing grantee already has
 * their own wrapped copy of the Item Key; only the `role` column changes.
 */
export async function transferOwnership(
  itemId: string,
  actorUserId: string,
  actorEmail: string,
  newOwnerGranteeType: "user" | "group",
  newOwnerGranteeId: string,
): Promise<void> {
  const { data: currentOwner, error: findError } = await supabase
    .from("item_keys")
    .select("grantee_type, grantee_id")
    .eq("item_id", itemId)
    .eq("role", "owner")
    .single();
  if (findError) throw findError;

  const { error: demoteError } = await supabase
    .from("item_keys")
    .update({ role: "edit_share" })
    .eq("item_id", itemId)
    .eq("grantee_type", currentOwner.grantee_type)
    .eq("grantee_id", currentOwner.grantee_id);
  if (demoteError) throw demoteError;

  const { error: promoteError } = await supabase
    .from("item_keys")
    .update({ role: "owner" })
    .eq("item_id", itemId)
    .eq("grantee_type", newOwnerGranteeType)
    .eq("grantee_id", newOwnerGranteeId);
  if (promoteError) throw promoteError;

  await logEvent(actorUserId, "role_changed", {
    itemId,
    detail: `Ownership transferred from ${currentOwner.grantee_type}:${currentOwner.grantee_id} to ${newOwnerGranteeType}:${newOwnerGranteeId}`,
  });

  const { data: item, error: itemError } = await supabase
    .from("items")
    .select("nonce, ciphertext")
    .eq("id", itemId)
    .single();
  if (itemError) throw itemError;

  const targetEmail =
    newOwnerGranteeType === "user"
      ? ((await supabase.from("user_directory").select("email").eq("id", newOwnerGranteeId).single()).data
          ?.email ?? newOwnerGranteeId)
      : ((await supabase.from("groups").select("name").eq("id", newOwnerGranteeId).single()).data?.name ??
          newOwnerGranteeId);

  const itemKey = await resolveItemKey(itemId, actorUserId);
  const envelope = await decryptEnvelope(itemKey, item.nonce, item.ciphertext);
  await logEnterpriseAuditEvent("ownership_transferred", actorEmail, targetEmail, envelope.title);
}
