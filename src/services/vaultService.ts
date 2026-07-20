/** Item CRUD — encrypts on write, decrypts on read. Web equivalent of vault_service.py. */
import { supabase } from "../api/supabase";
import { env } from "../config/env";
import { generateAesKeyBytes, importAesKey } from "../crypto/aes";
import { decryptEnvelope, encryptEnvelope } from "../crypto/envelope";
import { importPublicKey, wrapKey } from "../crypto/rsa";
import type { ItemRow } from "../types/db";
import type { ItemEnvelope, ItemType, VaultItem } from "../types/vaultItem";
import { getMyRole, resolveItemKey } from "./access";
import { logEvent } from "./auditService";
import {
  mockCreateItem,
  mockGetItem,
  mockHardDelete,
  mockListItems,
  mockRestoreFromTrash,
  mockSoftDelete,
  mockToggleFavorite,
  mockUpdateItem,
} from "./mockVaultStore";

export type Owner = { type: "user"; userId: string } | { type: "group"; groupId: string };

/** Looked up server-side rather than trusted from the caller — public keys are non-secret but must be the real one on file. */
async function fetchOwnerPublicKey(owner: Owner): Promise<string> {
  if (owner.type === "user") {
    const { data, error } = await supabase.from("user_directory").select("public_key").eq("id", owner.userId).single();
    if (error) throw error;
    return data.public_key;
  }
  const { data, error } = await supabase.from("groups").select("public_key").eq("id", owner.groupId).single();
  if (error) throw error;
  return data.public_key;
}

async function toVaultItem(row: ItemRow, userId: string): Promise<VaultItem> {
  const [itemKey, myRole] = await Promise.all([resolveItemKey(row.id, userId), getMyRole(row.id)]);
  const envelope = await decryptEnvelope(itemKey, row.nonce, row.ciphertext);
  return {
    id: row.id,
    itemType: row.item_type,
    ownerUserId: row.owner_user_id,
    ownerGroupId: row.owner_group_id,
    isFavorite: row.is_favorite,
    isDeleted: row.is_deleted,
    keyVersion: row.key_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    envelope,
    myRole,
  };
}

export async function createItem(
  itemType: ItemType,
  envelope: ItemEnvelope,
  owner: Owner,
): Promise<VaultItem> {
  if (env.mockAuthEnabled) {
    return mockCreateItem(itemType, envelope, owner.type === "user" ? owner.userId : "mock-group");
  }

  const itemKeyBytes = generateAesKeyBytes();
  const itemKey = await importAesKey(itemKeyBytes);
  const { nonce, ciphertext } = await encryptEnvelope(itemKey, envelope);

  const { data: itemRow, error: itemError } = await supabase
    .from("items")
    .insert({
      owner_user_id: owner.type === "user" ? owner.userId : null,
      owner_group_id: owner.type === "group" ? owner.groupId : null,
      item_type: itemType,
      nonce,
      ciphertext,
    })
    .select("*")
    .single();
  if (itemError) throw itemError;

  const recipientPublicKey = await importPublicKey(await fetchOwnerPublicKey(owner));
  const wrappedItemKey = await wrapKey(itemKeyBytes, recipientPublicKey);

  const grantedBy = owner.type === "user" ? owner.userId : null;
  const { error: keyError } = await supabase.from("item_keys").insert({
    item_id: itemRow.id,
    grantee_type: owner.type,
    grantee_id: owner.type === "user" ? owner.userId : owner.groupId,
    wrapped_item_key: wrappedItemKey,
    role: "owner",
    key_version: 1,
    granted_by: grantedBy,
  });
  if (keyError) throw keyError;

  if (owner.type === "user") await logEvent(owner.userId, "item_created", { itemId: itemRow.id });
  return toVaultItem(itemRow as ItemRow, owner.type === "user" ? owner.userId : "");
}

export async function getItem(itemId: string, userId: string): Promise<VaultItem | null> {
  if (env.mockAuthEnabled) return mockGetItem(itemId, userId);

  const { data, error } = await supabase.from("items").select("*").eq("id", itemId).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  const item = await toVaultItem(data as ItemRow, userId);
  await logEvent(userId, "item_viewed", { itemId });
  return item;
}

export async function listItems(
  userId: string,
  options: { includeDeleted?: boolean; favoritesOnly?: boolean } = {},
): Promise<VaultItem[]> {
  if (env.mockAuthEnabled) return mockListItems(userId, options);

  let query = supabase.from("items").select("*").eq("is_deleted", options.includeDeleted ?? false);
  if (options.favoritesOnly) query = query.eq("is_favorite", true);
  const { data, error } = await query.order("updated_at", { ascending: false });
  if (error) throw error;

  const items: VaultItem[] = [];
  for (const row of (data as ItemRow[]) ?? []) {
    try {
      items.push(await toVaultItem(row, userId));
    } catch (err) {
      console.error(`Failed to decrypt item ${row.id} — skipping.`, err);
    }
  }
  return items;
}

export async function updateItem(itemId: string, envelope: ItemEnvelope, userId: string): Promise<void> {
  if (env.mockAuthEnabled) return mockUpdateItem(itemId, envelope);

  const itemKey = await resolveItemKey(itemId, userId);
  const { nonce, ciphertext } = await encryptEnvelope(itemKey, envelope);
  const { error } = await supabase
    .from("items")
    .update({ nonce, ciphertext, updated_at: new Date().toISOString() })
    .eq("id", itemId);
  if (error) throw error;
  await logEvent(userId, "item_edited", { itemId });
}

export async function toggleFavorite(itemId: string, favorite: boolean): Promise<void> {
  if (env.mockAuthEnabled) return mockToggleFavorite(itemId, favorite);

  const { error } = await supabase
    .from("items")
    .update({ is_favorite: favorite, updated_at: new Date().toISOString() })
    .eq("id", itemId);
  if (error) throw error;
}

export async function softDelete(itemId: string, userId: string): Promise<void> {
  if (env.mockAuthEnabled) return mockSoftDelete(itemId);

  const { error } = await supabase
    .from("items")
    .update({ is_deleted: true, updated_at: new Date().toISOString() })
    .eq("id", itemId);
  if (error) throw error;
  await logEvent(userId, "item_deleted", { itemId });
}

export async function restoreFromTrash(itemId: string): Promise<void> {
  if (env.mockAuthEnabled) return mockRestoreFromTrash(itemId);

  const { error } = await supabase
    .from("items")
    .update({ is_deleted: false, updated_at: new Date().toISOString() })
    .eq("id", itemId);
  if (error) throw error;
}

export async function hardDelete(itemId: string): Promise<void> {
  if (env.mockAuthEnabled) return mockHardDelete(itemId);

  const { error } = await supabase.from("items").delete().eq("id", itemId);
  if (error) throw error;
}
