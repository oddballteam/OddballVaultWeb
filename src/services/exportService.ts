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
  /**
   * Present only in files from the desktop (Python) app — it stores the
   * AES-GCM auth tag as a separate base64 field. Web Crypto's own output
   * always has the tag appended to the ciphertext already, so this app's
   * own exports never set this. See normalizeCiphertext() below.
   */
  tag?: string;
}

/** Desktop app's inner item shape (app/services/export_service.py) — snake_case, `fields` dict instead of `envelope`. */
interface DesktopExportedItem {
  type: ItemType;
  title: string;
  fields: Record<string, unknown>;
  tags?: string;
  attachments?: { filename: string; mime_type: string | null; data: string }[];
  custom_fields?: { label: string; value: string; is_sensitive: boolean }[];
}

/** Maps desktop's snake_case field names (app/services/export_service.py's _ENCRYPTED_FIELD_NAMES) to the web's camelCase ItemEnvelope keys. */
const DESKTOP_FIELD_KEY_MAP: Record<string, keyof ItemEnvelope> = {
  username: "username",
  password: "password",
  url: "url",
  totp_secret: "totpSecret",
  notes: "notes",
  cardholder_name: "cardholderName",
  card_number: "cardNumber",
  card_expiry: "cardExpiry",
  card_cvv: "cardCvv",
  card_pin: "cardPin",
  full_name: "fullName",
  email: "email",
  phone: "phone",
  address_line1: "addressLine1",
  address_line2: "addressLine2",
  city: "city",
  state: "state",
  postal_code: "postalCode",
  country: "country",
  ssh_host: "sshHost",
  ssh_public_key: "sshPublicKey",
  ssh_private_key: "sshPrivateKey",
  service_name: "serviceName",
  key_name: "keyName",
  key_value: "keyValue",
  endpoint: "endpoint",
};

function isDesktopExportedItem(raw: unknown): raw is DesktopExportedItem {
  return typeof raw === "object" && raw !== null && "fields" in raw && "type" in raw;
}

/** Converts a desktop-app item (fields dict, snake_case) into this app's ExportedItem shape. */
function normalizeDesktopItem(raw: DesktopExportedItem): ExportedItem {
  const envelope: ItemEnvelope = { title: raw.title, tags: [], customFields: [] };
  for (const [desktopKey, value] of Object.entries(raw.fields)) {
    const webKey = DESKTOP_FIELD_KEY_MAP[desktopKey];
    if (webKey && typeof value === "string") (envelope as unknown as Record<string, unknown>)[webKey] = value;
  }
  envelope.tags = (raw.tags ?? "").split(",").map((t) => t.trim()).filter(Boolean);
  envelope.customFields = (raw.custom_fields ?? []).map((cf) => ({
    label: cf.label,
    value: cf.value,
    isSensitive: cf.is_sensitive,
  }));

  return {
    itemType: raw.type,
    envelope,
    attachments: (raw.attachments ?? []).map((a) => ({
      filename: a.filename,
      mimeType: a.mime_type,
      data: a.data,
    })),
  };
}

/**
 * Reconstructs the single ciphertext blob Web Crypto's AES-GCM expects
 * (ciphertext with the auth tag appended). This app's own exports already
 * have the tag appended (that's just what crypto.subtle.encrypt() returns);
 * the desktop app stores ciphertext and tag as two separate base64 fields
 * (app/crypto/aes.py::encrypt_with_key), so those need concatenating first.
 */
function normalizeCiphertext(envelope: ExportEnvelope): string {
  if (!envelope.tag) return envelope.ciphertext;
  const combined = new Uint8Array([...fromBase64(envelope.ciphertext), ...fromBase64(envelope.tag)]);
  return toBase64(combined);
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

  let payload: { items: (ExportedItem | DesktopExportedItem)[] };
  try {
    const json = await decryptString(exportKey, envelope.nonce, normalizeCiphertext(envelope));
    payload = JSON.parse(json);
  } catch {
    throw new Error("Incorrect export password, or the file is corrupted.");
  }

  let imported = 0;
  for (const raw of payload.items) {
    const exported = isDesktopExportedItem(raw) ? normalizeDesktopItem(raw) : raw;
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
