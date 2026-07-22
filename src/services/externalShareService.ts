/**
 * External one-time share links — lets a record be handed to someone outside
 * the org with no Okta identity, no Supabase account, and no app access.
 *
 * The share key is generated fresh per link and never sent to Supabase in any
 * form — it's embedded only in the URL fragment (#...), which browsers never
 * transmit over the network. The server (and this file's own insert calls)
 * only ever see ciphertext. See supabase/migrations/0012_external_one_time_shares.sql
 * for the table/RPC this talks to.
 */
import { generateAesKeyBytes, importAesKey } from "../crypto/aes";
import { fromBase64, toBase64 } from "../crypto/base64";
import { decryptEnvelope, encryptEnvelope } from "../crypto/envelope";
import type { ItemEnvelope } from "../types/vaultItem";
import { supabase } from "../api/supabase";
import type { ExternalShareRow } from "../types/db";
import { logEvent } from "./auditService";

export interface ExternalShareSummary {
  id: string;
  createdAt: string;
  expiresAt: string;
  burnedAt: string | null;
}

function toSummary(row: ExternalShareRow): ExternalShareSummary {
  return { id: row.id, createdAt: row.created_at, expiresAt: row.expires_at, burnedAt: row.burned_at };
}

export async function createExternalShare(
  envelope: ItemEnvelope,
  itemId: string,
  userId: string,
  expiryHours: number,
): Promise<string> {
  const keyBytes = generateAesKeyBytes();
  const key = await importAesKey(keyBytes);
  const { nonce, ciphertext } = await encryptEnvelope(key, envelope);

  const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000).toISOString();

  const { data, error } = await supabase
    .from("external_shares")
    .insert({ created_by: userId, nonce, ciphertext, expires_at: expiresAt })
    .select("id")
    .single();
  if (error) throw error;

  await logEvent(userId, "external_share_created", {
    itemId,
    detail: `Created one-time share link, expires in ${expiryHours}h`,
  });

  return `${window.location.origin}/shared/${data.id}#${toBase64(keyBytes)}`;
}

export async function listMyExternalShares(): Promise<ExternalShareSummary[]> {
  const { data, error } = await supabase
    .from("external_shares")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) throw error;
  return (data as ExternalShareRow[]).map(toSummary);
}

export async function revokeExternalShare(id: string): Promise<void> {
  const { error } = await supabase.from("external_shares").delete().eq("id", id);
  if (error) throw error;
}

/** Public, unauthenticated: burns the share on success. Returns null if invalid, expired, or already used. */
export async function claimExternalShare(id: string): Promise<{ nonce: string; ciphertext: string } | null> {
  const { data, error } = await supabase.rpc("claim_external_share", { share_id: id });
  if (error) throw error;
  const rows = data as { nonce: string; ciphertext: string }[];
  return rows[0] ?? null;
}

export async function decryptClaimedShare(
  claim: { nonce: string; ciphertext: string },
  keyBase64: string,
): Promise<ItemEnvelope> {
  const key = await importAesKey(fromBase64(keyBase64));
  return decryptEnvelope(key, claim.nonce, claim.ciphertext);
}
