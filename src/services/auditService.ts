/** Append-only audit log. No update/delete path exists here or in RLS — matches the desktop app's invariant. */
import { supabase } from "../api/supabase";
import type { AuditEventType, AuditLogRow, EnterpriseAuditAction } from "../types/db";

export async function logEvent(
  userId: string,
  eventType: AuditEventType,
  options: { itemId?: string; detail?: string } = {},
): Promise<void> {
  const { error } = await supabase.from("audit_log").insert({
    user_id: userId,
    event_type: eventType,
    item_id: options.itemId ?? null,
    detail: options.detail ?? null,
  });
  if (error) console.error(`Failed to write audit event ${eventType}:`, error.message);
}

export async function getEvents(limit = 100, offset = 0): Promise<AuditLogRow[]> {
  const { data, error } = await supabase
    .from("audit_log")
    .select("*")
    .order("occurred_at", { ascending: false })
    .range(offset, offset + limit - 1);
  if (error) throw error;
  return data as AuditLogRow[];
}

/**
 * Writes to the separate, IT/Sec-Admin-only `audit_logs` table (plural —
 * see 0007_enterprise_admin.sql). Called by sharingService at the moment of
 * a share/transfer, while the item's title is already decrypted client-side
 * for the operation itself — this is the only place that plaintext title
 * ever gets written anywhere, and only for items someone deliberately shared.
 */
export async function logEnterpriseAuditEvent(
  action: EnterpriseAuditAction,
  actorEmail: string,
  targetEmail: string,
  itemName: string,
): Promise<void> {
  const { error } = await supabase.from("audit_logs").insert({
    action,
    actor_email: actorEmail,
    target_email: targetEmail,
    item_name: itemName,
  });
  if (error) console.error(`Failed to write enterprise audit event ${action}:`, error.message);
}
