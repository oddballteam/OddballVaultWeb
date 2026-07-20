/**
 * Encrypted `.ovault` export/import — entirely client-side, no Supabase
 * round-trip needed beyond the reads already used to view the items. The
 * export password is always separate from the master password; export key
 * material is never derived from or stored alongside vault crypto.
 */
import { decryptString, encryptString } from "../crypto/aes";
import { fromBase64, toBase64 } from "../crypto/base64";
import { deriveMasterKey, generateSalt } from "../crypto/kdf";
import { importAesKey } from "../crypto/aes";
import type { ItemEnvelope, ItemType } from "../types/vaultItem";
import { downloadAttachment, listAttachments, uploadAttachment } from "./attachmentService";
import { createItem, getItem } from "./vaultService";
import { logEvent } from "./auditService";

const FORMAT = "oddball-vault-record";
const FORMAT_VERSION = 2;

interface ExportedAttachment {
  filename: string;
  mimeType: string | null;
  data: string; // base64 plaintext bytes
}

interface ExportedItem {
  itemType: ItemType;
  envelope: ItemEnvelope;
  attachments: ExportedAttachment[];
}

interface ExportEnvelope {
  format: string;
  version: number;
  createdAt: string;
  itemCount: number;
  salt: string;
  nonce: string;
  ciphertext: string;
}

export async function exportItems(itemIds: string[], exportPassword: string, userId: string): Promise<Blob> {
  if (!exportPassword) throw new Error("Export password must not be empty.");

  const items: ExportedItem[] = [];
  for (const id of itemIds) {
    const item = await getItem(id, userId);
    if (!item) continue;

    const attachmentSummaries = await listAttachments(id, userId);
    const attachments: ExportedAttachment[] = [];
    for (const summary of attachmentSummaries) {
      const { filename, bytes, mimeType } = await downloadAttachment(summary.id, userId);
      attachments.push({ filename, mimeType, data: toBase64(bytes) });
    }

    items.push({ itemType: item.itemType, envelope: item.envelope, attachments });
  }

  const salt = generateSalt();
  const exportKeyBytes = await deriveMasterKey(exportPassword, salt);
  const exportKey = await importAesKey(exportKeyBytes);
  const { nonce, ciphertext } = await encryptString(exportKey, JSON.stringify({ items }));

  const envelope: ExportEnvelope = {
    format: FORMAT,
    version: FORMAT_VERSION,
    createdAt: new Date().toISOString(),
    itemCount: items.length,
    salt: toBase64(salt),
    nonce,
    ciphertext,
  };

  await logEvent(userId, "export", { detail: `Exported ${items.length} item(s)` });
  return new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
}

export async function importItems(
  file: File,
  exportPassword: string,
  owner: Parameters<typeof createItem>[2],
  userId: string,
): Promise<{ imported: number }> {
  const envelope = JSON.parse(await file.text()) as ExportEnvelope;
  if (envelope.format !== FORMAT || envelope.version !== FORMAT_VERSION) {
    throw new Error(`Unrecognised export file (format=${envelope.format}, version=${envelope.version}).`);
  }

  const salt = fromBase64(envelope.salt);
  const exportKeyBytes = await deriveMasterKey(exportPassword, salt);
  const exportKey = await importAesKey(exportKeyBytes);

  let payload: { items: ExportedItem[] };
  try {
    const json = await decryptString(exportKey, envelope.nonce, envelope.ciphertext);
    payload = JSON.parse(json);
  } catch {
    throw new Error("Incorrect export password, or the file is corrupted.");
  }

  let imported = 0;
  for (const exported of payload.items) {
    const created = await createItem(exported.itemType, exported.envelope, owner);
    for (const attachment of exported.attachments) {
      const bytes = fromBase64(attachment.data);
      const restoredFile = new File([bytes], attachment.filename, { type: attachment.mimeType ?? undefined });
      await uploadAttachment(created.id, restoredFile, userId);
    }
    imported++;
  }

  await logEvent(userId, "import", { detail: `Imported ${imported} item(s)` });
  return { imported };
}
