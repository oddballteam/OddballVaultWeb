import type { User } from "@supabase/supabase-js";
import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";

export const ADMIN_GROUP_NAME = "IT/Sec Admin";

/**
 * The full list of Okta groups synced onto the session — general-purpose,
 * used both for the admin check below and (going forward) for group-based
 * folder access once RLS is rewritten to key off this directly instead of
 * the app-managed group_memberships table.
 */
export function getUserGroups(user: User | null): string[] {
  const groups = user?.app_metadata?.groups;
  return Array.isArray(groups) ? groups : [];
}

/**
 * This only decides whether to *show* the admin dashboard — it is not the
 * real security boundary. The actual authorization is enforced server-side:
 * RLS on audit_logs and the internal check inside nuke_user_vault() both
 * re-check the same "IT/Sec Admin" group claim from the JWT independently of
 * this client-side gate, since a client-side check alone can always be
 * bypassed (e.g. calling Supabase directly).
 *
 * Reads from app_metadata because that's where Supabase's own JWT surfaces
 * it — see supabase/migrations/0008_okta_groups_via_app_metadata.sql for
 * how Okta's groups claim gets copied in via a Custom Access Token Hook.
 * That hook requires a manual dashboard step; if it isn't enabled, this
 * will read as an empty array for everyone.
 */
export function hasAdminGroup(user: User | null): boolean {
  const groups = getUserGroups(user);

  // TEMPORARY DEBUG LOG — remove once the Okta "groups" claim is confirmed
  // to be propagating correctly end to end. If this logs [] or undefined
  // for a user who IS assigned "IT/Sec Admin" in Okta, the bug is upstream
  // of this function, most likely one of:
  //   1. The Custom Access Token Hook (0008 migration) isn't enabled in
  //      Supabase Dashboard → Authentication → Hooks — this is a manual
  //      step that isn't run automatically by applying the migration.
  //   2. Okta isn't actually returning a "groups" claim to Supabase (check
  //      the Okta app's Groups Claim config and the requested scopes).
  //   3. auth.identities.identity_data has no "groups" key for this user —
  //      query it directly to confirm what Supabase actually received.
  console.log("[adminAccess] user.app_metadata.groups:", groups);

  return groups.includes(ADMIN_GROUP_NAME);
}

/** Strictly rejects unless ADMIN_GROUP_NAME is present — no partial match, no case-insensitivity, no fallback. */
export function AdminRoute({ isAdmin, children }: { isAdmin: boolean; children: ReactNode }) {
  if (!isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}
