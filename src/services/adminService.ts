/**
 * IT/Sec Admin dashboard data access. RLS on `audit_logs` and the internal
 * check inside `nuke_user_vault()` are the real authorization boundary —
 * this module just calls them; it grants nothing on its own.
 */
import { supabase } from "../api/supabase";
import type { EnterpriseAuditLogRow } from "../types/db";

export async function listAuditLogs(): Promise<EnterpriseAuditLogRow[]> {
  const { data, error } = await supabase
    .from("audit_logs")
    .select("*")
    .order("timestamp", { ascending: false });
  if (error) throw error;
  return data as EnterpriseAuditLogRow[];
}

/** Deletes every item owned by the target user. Returns the number of items deleted. */
export async function nukeUserVault(target: { email: string } | { userId: string }): Promise<number> {
  const { data, error } = await supabase.rpc("nuke_user_vault", {
    target_email: "email" in target ? target.email : null,
    target_user_id: "userId" in target ? target.userId : null,
  });
  if (error) throw error;
  return data as number;
}
