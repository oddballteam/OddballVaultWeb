/**
 * Encrypted file attachments in Supabase Storage. Attachments share their
 * parent item's Item Key — no separate wrapping system — so plaintext bytes
 * never touch the network or Supabase, only nonce+ciphertext blobs.
 */
import { supabase } from "../api/supabase";
import { decryptBytes, decryptString, encryptBytes, encryptString } from "../crypto/aes";
import { fromBase64, toBase64 } from "../crypto/base64";
import type { AttachmentRow } from "../types/db";
import { resolveItemKey } from "./access";

const BUCKET = "attachments";
const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB, matches the desktop app's limit

export interface AttachmentSummary {
  id: string;
  filename: string;
  mimeType: string | null;
  sizeBytes: number;
  createdAt: string;
}

function storagePath(itemId: string, attachmentId: string): string {
  return `${itemId}/${attachmentId}`;
}

export async function uploadAttachment(itemId: string, file: File, userId: string): Promise<AttachmentSummary> {
  if (file.size > MAX_FILE_SIZE_BYTES) {
    throw new Error(`File exceeds the 50 MB limit (${file.size.toLocaleString()} bytes).`);
  }
  const itemKey = await resolveItemKey(itemId, userId);

  const rawBytes = new Uint8Array(await file.arrayBuffer());
  const { nonce, ciphertext } = await encryptBytes(itemKey, rawBytes);
  const encryptedFilename = await encryptString(itemKey, file.name);

  const attachmentId = crypto.randomUUID();
  const path = storagePath(itemId, attachmentId);

  const { error: uploadError } = await supabase.storage
    .from(BUCKET)
    .upload(path, new Blob([fromBase64(ciphertext)]), { contentType: "application/octet-stream" });
  if (uploadError) throw uploadError;

  const { error: insertError } = await supabase.from("attachments").insert({
    id: attachmentId,
    item_id: itemId,
    nonce,
    encrypted_filename: encryptedFilename.ciphertext,
    filename_nonce: encryptedFilename.nonce,
    mime_type: file.type || "application/octet-stream",
    size_bytes: file.size,
    storage_path: path,
  });
  if (insertError) throw insertError;

  return { id: attachmentId, filename: file.name, mimeType: file.type, sizeBytes: file.size, createdAt: new Date().toISOString() };
}

export async function listAttachments(itemId: string, userId: string): Promise<AttachmentSummary[]> {
  const itemKey = await resolveItemKey(itemId, userId);
  const { data, error } = await supabase
    .from("attachments")
    .select("*")
    .eq("item_id", itemId)
    .order("created_at");
  if (error) throw error;

  const rows = (data as AttachmentRow[]) ?? [];
  return Promise.all(
    rows.map(async (row) => ({
      id: row.id,
      filename: await decryptString(itemKey, row.filename_nonce, row.encrypted_filename),
      mimeType: row.mime_type,
      sizeBytes: row.size_bytes,
      createdAt: row.created_at,
    })),
  );
}

export async function downloadAttachment(
  attachmentId: string,
  userId: string,
): Promise<{ filename: string; bytes: Uint8Array; mimeType: string | null }> {
  const { data: row, error } = await supabase.from("attachments").select("*").eq("id", attachmentId).single();
  if (error) throw error;
  const attachment = row as AttachmentRow;

  const itemKey = await resolveItemKey(attachment.item_id, userId);
  const filename = await decryptString(itemKey, attachment.filename_nonce, attachment.encrypted_filename);

  const { data: blob, error: downloadError } = await supabase.storage
    .from(BUCKET)
    .download(attachment.storage_path);
  if (downloadError) throw downloadError;

  const ciphertext = toBase64(new Uint8Array(await blob.arrayBuffer()));
  const bytes = await decryptBytes(itemKey, attachment.nonce, ciphertext);
  return { filename, bytes, mimeType: attachment.mime_type };
}

export async function deleteAttachment(attachmentId: string): Promise<void> {
  const { data: row, error } = await supabase.from("attachments").select("storage_path").eq("id", attachmentId).single();
  if (error) throw error;
  await supabase.storage.from(BUCKET).remove([row.storage_path]);
  const { error: deleteError } = await supabase.from("attachments").delete().eq("id", attachmentId);
  if (deleteError) throw deleteError;
}

/**
 * Called during Item Key rotation (see sharingService.revokeAccess) — every
 * attachment must be re-encrypted under the new key, or it becomes
 * permanently undecryptable the moment the old key is no longer wrapped for
 * anyone.
 */
export async function reencryptAttachmentsForRotation(
  itemId: string,
  oldItemKey: CryptoKey,
  newItemKey: CryptoKey,
): Promise<void> {
  const { data, error } = await supabase.from("attachments").select("*").eq("item_id", itemId);
  if (error) throw error;

  for (const row of (data as AttachmentRow[]) ?? []) {
    const { data: blob, error: downloadError } = await supabase.storage.from(BUCKET).download(row.storage_path);
    if (downloadError) throw downloadError;

    const oldCiphertext = toBase64(new Uint8Array(await blob.arrayBuffer()));
    const plaintext = await decryptBytes(oldItemKey, row.nonce, oldCiphertext);
    const filename = await decryptString(oldItemKey, row.filename_nonce, row.encrypted_filename);

    const reencrypted = await encryptBytes(newItemKey, plaintext);
    const reencryptedFilename = await encryptString(newItemKey, filename);

    const { error: uploadError } = await supabase.storage
      .from(BUCKET)
      .upload(row.storage_path, new Blob([fromBase64(reencrypted.ciphertext)]), {
        contentType: "application/octet-stream",
        upsert: true,
      });
    if (uploadError) throw uploadError;

    const { error: updateError } = await supabase
      .from("attachments")
      .update({
        nonce: reencrypted.nonce,
        encrypted_filename: reencryptedFilename.ciphertext,
        filename_nonce: reencryptedFilename.nonce,
      })
      .eq("id", row.id);
    if (updateError) throw updateError;
  }
}
