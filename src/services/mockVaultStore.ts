/**
 * localStorage-backed stand-in for the Supabase `items` table, used only
 * when VITE_MOCK_AUTH is on (see vaultService.ts). Records are stored as
 * plain JSON — there's no real key material to encrypt under in mock mode
 * (the session was never actually unlocked against a real vault), and this
 * exists purely so the UI/layout can be reviewed with working CRUD, not as
 * a security boundary of any kind.
 */
import type { ItemEnvelope, ItemRole, ItemType, VaultItem } from "../types/vaultItem";

const STORAGE_KEY = "oddball-vault-mock-items";

interface MockRecord {
  id: string;
  itemType: ItemType;
  envelope: ItemEnvelope;
  isFavorite: boolean;
  isDeleted: boolean;
  createdAt: string;
  updatedAt: string;
}

function loadAll(): MockRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as MockRecord[]) : [];
  } catch {
    return [];
  }
}

function saveAll(records: MockRecord[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
}

function toVaultItem(record: MockRecord, userId: string): VaultItem {
  const myRole: ItemRole = "owner";
  return {
    id: record.id,
    itemType: record.itemType,
    ownerUserId: userId,
    ownerGroupId: null,
    isFavorite: record.isFavorite,
    isDeleted: record.isDeleted,
    keyVersion: 1,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    envelope: record.envelope,
    myRole,
  };
}

export function mockListItems(
  userId: string,
  options: { includeDeleted?: boolean; favoritesOnly?: boolean } = {},
): VaultItem[] {
  const wantDeleted = options.includeDeleted ?? false;
  let records = loadAll().filter((r) => r.isDeleted === wantDeleted);
  if (options.favoritesOnly) records = records.filter((r) => r.isFavorite);
  records.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  return records.map((r) => toVaultItem(r, userId));
}

export function mockGetItem(itemId: string, userId: string): VaultItem | null {
  const record = loadAll().find((r) => r.id === itemId);
  return record ? toVaultItem(record, userId) : null;
}

export function mockCreateItem(itemType: ItemType, envelope: ItemEnvelope, userId: string): VaultItem {
  const now = new Date().toISOString();
  const record: MockRecord = {
    id: crypto.randomUUID(),
    itemType,
    envelope,
    isFavorite: false,
    isDeleted: false,
    createdAt: now,
    updatedAt: now,
  };
  const all = loadAll();
  all.push(record);
  saveAll(all);
  return toVaultItem(record, userId);
}

function mutate(itemId: string, apply: (record: MockRecord) => void): void {
  const all = loadAll();
  const record = all.find((r) => r.id === itemId);
  if (!record) throw new Error("Item not found.");
  apply(record);
  record.updatedAt = new Date().toISOString();
  saveAll(all);
}

export function mockUpdateItem(itemId: string, envelope: ItemEnvelope): void {
  mutate(itemId, (record) => {
    record.envelope = envelope;
  });
}

export function mockToggleFavorite(itemId: string, favorite: boolean): void {
  mutate(itemId, (record) => {
    record.isFavorite = favorite;
  });
}

export function mockSoftDelete(itemId: string): void {
  mutate(itemId, (record) => {
    record.isDeleted = true;
  });
}

export function mockRestoreFromTrash(itemId: string): void {
  mutate(itemId, (record) => {
    record.isDeleted = false;
  });
}

export function mockHardDelete(itemId: string): void {
  saveAll(loadAll().filter((r) => r.id !== itemId));
}
