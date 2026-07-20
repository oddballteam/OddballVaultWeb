/**
 * Group Folder membership management. Adding a member only costs one new
 * RSA-wrap of the existing Group KEK (cheap). Removing a member requires a
 * real re-key: a new group keypair + KEK, re-wrapped for every remaining
 * member, and every group-owned item's wrapped Item Key re-wrapped under
 * the new group public key — otherwise the removed member's cached copy of
 * the old group private key still unlocks everything the group can see.
 *
 * Note this is cheaper than it sounds: only the *wrapping* of each item's
 * Item Key changes, not the item's content — the AES key value itself is
 * unchanged, so no bulk re-encryption of item content or attachments is
 * needed here (contrast with sharingService.revokeAccess, where the Item
 * Key value itself must change because a user held a *direct* unwrapped
 * copy of it).
 */
import { supabase } from "../api/supabase";
import { unwrapGroupPrivateKey, unwrapKekForMember, wrapKekForMember, createGroupKeyMaterial } from "../crypto/groupKeys";
import { importPublicKey, unwrapKey, wrapKey } from "../crypto/rsa";
import { vaultSession } from "../crypto/session";
import type { GroupMembershipRow, GroupRow, ItemKeyRow } from "../types/db";
import { isAllowedTenantEmail } from "../utils/tenantEmail";
import { logEvent } from "./auditService";

export interface GroupMemberSummary {
  userId: string;
  email: string;
  role: "member" | "admin";
}

export async function listMyGroups(userId: string): Promise<GroupRow[]> {
  const { data, error } = await supabase
    .from("group_memberships")
    .select("groups(*)")
    .eq("user_id", userId);
  if (error) throw error;
  return (data ?? []).map((row) => row.groups as unknown as GroupRow);
}

export async function listMembers(groupId: string): Promise<GroupMemberSummary[]> {
  const { data, error } = await supabase
    .from("group_memberships")
    .select("user_id, role, user_directory(email)")
    .eq("group_id", groupId);
  if (error) throw error;
  return (data ?? []).map((row) => ({
    userId: row.user_id,
    role: row.role as "member" | "admin",
    email: (row.user_directory as unknown as { email: string } | null)?.email ?? row.user_id,
  }));
}

/** Requires the actor to already be a group admin (enforced by RLS on group_memberships insert). */
export async function addMember(
  groupId: string,
  actorUserId: string,
  newMemberEmail: string,
  role: "member" | "admin" = "member",
): Promise<void> {
  if (!isAllowedTenantEmail(newMemberEmail)) {
    throw new Error("Group membership is limited to @oddball.io addresses in this environment.");
  }

  const { data: group, error: groupError } = await supabase.from("groups").select("*").eq("id", groupId).single();
  if (groupError) throw groupError;

  const { data: actorMembership, error: actorError } = await supabase
    .from("group_memberships")
    .select("wrapped_group_kek")
    .eq("group_id", groupId)
    .eq("user_id", actorUserId)
    .single();
  if (actorError) throw actorError;

  const { data: newMember, error: memberError } = await supabase
    .from("user_directory")
    .select("id, public_key")
    .eq("email", newMemberEmail)
    .single();
  if (memberError) throw new Error(`No user found with email ${newMemberEmail}.`);

  const kek = await unwrapKekForMember(actorMembership.wrapped_group_kek, vaultSession.getPrivateKey());
  const newMemberPublicKey = await importPublicKey(newMember.public_key);
  const wrappedKek = await wrapKekForMember(kek, newMemberPublicKey);

  const { error: insertError } = await supabase.from("group_memberships").insert({
    group_id: groupId,
    user_id: newMember.id,
    wrapped_group_kek: wrappedKek,
    role,
  });
  if (insertError) throw insertError;

  await logEvent(actorUserId, "item_shared", { detail: `Added ${newMemberEmail} to group ${(group as GroupRow).name}` });
}

/** Requires the actor to be a group admin. Performs the full re-key described above. */
export async function removeMemberAndRekey(groupId: string, memberIdToRemove: string, actorUserId: string): Promise<void> {
  const { data: group, error: groupError } = await supabase.from("groups").select("*").eq("id", groupId).single();
  if (groupError) throw groupError;
  const oldGroup = group as GroupRow;

  const { data: actorMembership, error: actorError } = await supabase
    .from("group_memberships")
    .select("wrapped_group_kek")
    .eq("group_id", groupId)
    .eq("user_id", actorUserId)
    .single();
  if (actorError) throw actorError;

  const privateKey = vaultSession.getPrivateKey();
  const oldKek = await unwrapKekForMember(actorMembership.wrapped_group_kek, privateKey);
  const oldGroupPrivateKey = await unwrapGroupPrivateKey(oldGroup.private_key_nonce, oldGroup.encrypted_private_key, oldKek);

  const { data: memberRows, error: membersError } = await supabase
    .from("group_memberships")
    .select("*")
    .eq("group_id", groupId);
  if (membersError) throw membersError;
  const remainingMembers = ((memberRows as GroupMembershipRow[]) ?? []).filter((m) => m.user_id !== memberIdToRemove);

  const newMaterial = await createGroupKeyMaterial();

  for (const member of remainingMembers) {
    const { data: userRow, error: userError } = await supabase
      .from("user_directory")
      .select("public_key")
      .eq("id", member.user_id)
      .single();
    if (userError) throw userError;

    const publicKey = await importPublicKey(userRow.public_key);
    const wrappedKek = await wrapKekForMember(newMaterial.kek, publicKey);
    const { error: updateMemberError } = await supabase
      .from("group_memberships")
      .update({ wrapped_group_kek: wrappedKek })
      .eq("group_id", groupId)
      .eq("user_id", member.user_id);
    if (updateMemberError) throw updateMemberError;
  }

  const { error: removeError } = await supabase
    .from("group_memberships")
    .delete()
    .eq("group_id", groupId)
    .eq("user_id", memberIdToRemove);
  if (removeError) throw removeError;

  const { data: groupItemGrants, error: grantsError } = await supabase
    .from("item_keys")
    .select("*")
    .eq("grantee_type", "group")
    .eq("grantee_id", groupId);
  if (grantsError) throw grantsError;

  const newGroupPublicKey = await importPublicKey(newMaterial.publicKeySpki);
  for (const grant of (groupItemGrants as ItemKeyRow[]) ?? []) {
    const itemKeyRaw = await unwrapKey(grant.wrapped_item_key, oldGroupPrivateKey);
    const rewrapped = await wrapKey(itemKeyRaw, newGroupPublicKey);
    const { error: rewrapError } = await supabase
      .from("item_keys")
      .update({ wrapped_item_key: rewrapped })
      .eq("item_id", grant.item_id)
      .eq("grantee_type", "group")
      .eq("grantee_id", groupId);
    if (rewrapError) throw rewrapError;
  }

  const { error: groupUpdateError } = await supabase
    .from("groups")
    .update({
      public_key: newMaterial.publicKeySpki,
      encrypted_private_key: newMaterial.encryptedPrivateKey,
      private_key_nonce: newMaterial.encryptedPrivateKeyNonce,
      key_version: oldGroup.key_version + 1,
    })
    .eq("id", groupId);
  if (groupUpdateError) throw groupUpdateError;

  await logEvent(actorUserId, "group_key_rotated", {
    detail: `Removed member from ${oldGroup.name}, rotated group keypair to v${oldGroup.key_version + 1}`,
  });
}
