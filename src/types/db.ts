/** Row shapes as they exist in Supabase — snake_case, matching the SQL migrations exactly. */

export interface UserDirectoryRow {
  id: string;
  email: string;
  public_key: string;
  created_at: string;
}

export interface AppUserRow {
  id: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  kdf_salt: string; // base64
  kdf_time_cost: number;
  kdf_memory_cost: number;
  kdf_parallelism: number;
  key_check_ciphertext: string;
  key_check_nonce: string;
  created_at: string;
}

export interface GroupRow {
  id: string;
  name: string;
  okta_group_id: string;
  public_key: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  key_version: number;
  created_at: string;
}

export interface GroupMembershipRow {
  group_id: string;
  user_id: string;
  wrapped_group_kek: string;
  role: "member" | "admin";
  added_at: string;
}

export type ItemTypeRow = "login" | "note" | "card" | "identity" | "ssh_key" | "api_credential";

export interface ItemRow {
  id: string;
  owner_user_id: string | null;
  owner_group_id: string | null;
  item_type: ItemTypeRow;
  is_favorite: boolean;
  is_deleted: boolean;
  nonce: string;
  ciphertext: string;
  key_version: number;
  created_at: string;
  updated_at: string;
}

export type ItemRoleRow = "owner" | "edit_share" | "edit" | "view";

export interface ItemKeyRow {
  item_id: string;
  grantee_type: "user" | "group";
  grantee_id: string;
  wrapped_item_key: string;
  role: ItemRoleRow;
  key_version: number;
  granted_by: string | null;
  granted_at: string;
}

export interface AttachmentRow {
  id: string;
  item_id: string;
  nonce: string;
  encrypted_filename: string;
  filename_nonce: string;
  mime_type: string | null;
  size_bytes: number;
  storage_path: string;
  created_at: string;
}

export type AuditEventType =
  | "unlock"
  | "lock"
  | "failed_unlock"
  | "item_created"
  | "item_viewed"
  | "item_edited"
  | "item_deleted"
  | "item_shared"
  | "item_unshared"
  | "role_changed"
  | "item_key_rotated"
  | "group_key_rotated"
  | "export"
  | "import"
  | "password_changed"
  | "vault_reset"
  | "group_folder_created"
  | "group_folder_renamed"
  | "group_folder_deleted";

export interface AuditLogRow {
  id: string;
  user_id: string;
  event_type: AuditEventType;
  item_id: string | null;
  detail: string | null;
  occurred_at: string;
}

/**
 * The enterprise IT/Sec-Admin-only trail (table `audit_logs`, plural) — a
 * different table from `audit_log` above. See the migration comment in
 * 0007_enterprise_admin.sql for why these are deliberately separate.
 */
export type EnterpriseAuditAction = "item_shared" | "ownership_transferred" | "vault_wiped";

export interface EnterpriseAuditLogRow {
  id: string;
  timestamp: string;
  action: EnterpriseAuditAction;
  actor_email: string;
  target_email: string;
  item_name: string;
}
