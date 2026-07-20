export type ItemType = "login" | "note" | "card" | "identity" | "ssh_key" | "api_credential";

export const ITEM_TYPE_LABELS: Record<ItemType, string> = {
  login: "Login",
  note: "Secure Note",
  card: "Credit Card",
  identity: "Identity",
  ssh_key: "SSH Key",
  api_credential: "API Credential",
};

export type ItemRole = "owner" | "edit_share" | "edit" | "view";

export const ROLE_LABELS: Record<ItemRole, string> = {
  owner: "Owner",
  edit_share: "Edit & Share",
  edit: "Edit",
  view: "View",
};

export interface CustomField {
  label: string;
  value: string;
  isSensitive: boolean;
}

/**
 * Everything about an item that must never reach Supabase in plaintext.
 * This whole object is JSON-stringified and AES-256-GCM-encrypted as one
 * unit under the item's Item Key — see crypto/envelope.ts.
 */
export interface ItemEnvelope {
  title: string;
  tags: string[];

  // Login
  username?: string;
  password?: string;
  url?: string;
  totpSecret?: string;

  // Note (also used for freeform notes on any type)
  notes?: string;

  // Credit card
  cardholderName?: string;
  cardNumber?: string;
  cardExpiry?: string;
  cardCvv?: string;
  cardPin?: string;

  // Identity
  fullName?: string;
  email?: string;
  phone?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;

  // SSH key
  sshHost?: string;
  sshPublicKey?: string;
  sshPrivateKey?: string;

  // API credential
  serviceName?: string;
  keyName?: string;
  keyValue?: string;
  endpoint?: string;

  customFields: CustomField[];
}

export interface VaultItem {
  id: string;
  itemType: ItemType;
  ownerUserId: string | null;
  ownerGroupId: string | null;
  isFavorite: boolean;
  isDeleted: boolean;
  keyVersion: number;
  createdAt: string;
  updatedAt: string;
  envelope: ItemEnvelope;
  /** The caller's own effective role on this item — drives which UI actions are offered. */
  myRole: ItemRole;
}

export function emptyEnvelope(title: string): ItemEnvelope {
  return { title, tags: [], customFields: [] };
}
