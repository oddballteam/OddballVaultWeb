/**
 * Resolves what the current session can actually do with a given item:
 * which Item Key to use for decrypt/encrypt (direct grant first, falling
 * back to whichever group grant the user is a member of), and the most
 * permissive role across all of their applicable grants (RLS enforces the
 * same access server-side — this just mirrors it for the UI).
 */
import { supabase } from "../api/supabase";
import { importAesKey } from "../crypto/aes";
import { unwrapGroupPrivateKey, unwrapKekForMember } from "../crypto/groupKeys";
import { unwrapKey } from "../crypto/rsa";
import { vaultSession } from "../crypto/session";
import type { ItemRole } from "../types/vaultItem";

const ROLE_RANK: Record<ItemRole, number> = { view: 0, edit: 1, edit_share: 2, owner: 3 };

export function mostPermissiveRole(roles: ItemRole[]): ItemRole {
  if (roles.length === 0) throw new Error("No applicable role found.");
  return roles.reduce((best, role) => (ROLE_RANK[role] > ROLE_RANK[best] ? role : best));
}

export async function getMyRole(itemId: string): Promise<ItemRole> {
  const { data, error } = await supabase.rpc("my_item_grant_roles", { target_item_id: itemId });
  if (error) throw error;
  const roles = (data as { role: ItemRole }[] | ItemRole[]).map((r) =>
    typeof r === "string" ? r : r.role,
  );
  return mostPermissiveRole(roles);
}

/**
 * Returns the raw Item Key bytes — needed when re-wrapping the key for a new
 * share recipient (RSA-OAEP-wrapping requires the actual key bytes, which a
 * non-extractable CryptoKey deliberately cannot give up). Use
 * resolveItemKey() instead for local encrypt/decrypt of item content.
 */
export async function resolveItemKeyRaw(itemId: string, userId: string): Promise<Uint8Array> {
  const privateKey = vaultSession.getPrivateKey();

  const { data: directGrant, error: directError } = await supabase
    .from("item_keys")
    .select("wrapped_item_key")
    .eq("item_id", itemId)
    .eq("grantee_type", "user")
    .eq("grantee_id", userId)
    .maybeSingle();
  if (directError) throw directError;

  if (directGrant) {
    return unwrapKey(directGrant.wrapped_item_key, privateKey);
  }

  const { data: groupGrants, error: groupGrantsError } = await supabase
    .from("item_keys")
    .select("grantee_id, wrapped_item_key")
    .eq("item_id", itemId)
    .eq("grantee_type", "group");
  if (groupGrantsError) throw groupGrantsError;

  for (const grant of groupGrants ?? []) {
    const { data: membership } = await supabase
      .from("group_memberships")
      .select("wrapped_group_kek")
      .eq("group_id", grant.grantee_id)
      .eq("user_id", userId)
      .maybeSingle();
    if (!membership) continue;

    const { data: group, error: groupError } = await supabase
      .from("groups")
      .select("encrypted_private_key, private_key_nonce")
      .eq("id", grant.grantee_id)
      .single();
    if (groupError) throw groupError;

    const kek = await unwrapKekForMember(membership.wrapped_group_kek, privateKey);
    const groupPrivateKey = await unwrapGroupPrivateKey(
      group.private_key_nonce,
      group.encrypted_private_key,
      kek,
    );
    return unwrapKey(grant.wrapped_item_key, groupPrivateKey);
  }

  throw new Error("No accessible key found for this item.");
}

export async function resolveItemKey(itemId: string, userId: string): Promise<CryptoKey> {
  return importAesKey(await resolveItemKeyRaw(itemId, userId));
}
