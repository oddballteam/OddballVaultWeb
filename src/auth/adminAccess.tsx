import type { Session } from "@supabase/supabase-js";
import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";

export const ADMIN_GROUP_NAME = "IT/Sec Admin";

/** Base64url (JWT-flavored) decode — plain atob() rejects the -/_ alphabet and missing padding JWTs use. */
function decodeJwtPayload(accessToken: string): Record<string, unknown> | null {
  const segment = accessToken.split(".")[1];
  if (!segment) return null;
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  try {
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

/**
 * The full list of Okta groups synced onto the session — general-purpose,
 * used both for the admin check below and (going forward) for group-based
 * folder access once RLS is rewritten to key off this directly instead of
 * the app-managed group_memberships table.
 *
 * Reads app_metadata off the DECODED ACCESS TOKEN, not session.user —
 * the Custom Access Token Hook (supabase/migrations/0008_okta_groups_via_app_metadata.sql)
 * injects Okta's groups claim into the minted JWT only. It never writes back
 * to the underlying auth.users row, so session.user.app_metadata (sourced
 * from GoTrue's stored user record) never reflects it — only the token
 * itself does.
 */
export function getUserGroups(session: Session | null): string[] {
  if (!session) return [];
  const claims = decodeJwtPayload(session.access_token);
  const groups = (claims?.app_metadata as { groups?: unknown } | undefined)?.groups;
  if (Array.isArray(groups)) return groups;
  // Mock auth's access_token isn't a real JWT — fall back to the mock user object.
  const fallback = session.user?.app_metadata?.groups;
  return Array.isArray(fallback) ? fallback : [];
}

/**
 * This only decides whether to *show* the admin dashboard — it is not the
 * real security boundary. The actual authorization is enforced server-side:
 * RLS on audit_logs and the internal check inside nuke_user_vault() both
 * re-check the same "IT/Sec Admin" group claim from the JWT independently of
 * this client-side gate, since a client-side check alone can always be
 * bypassed (e.g. calling Supabase directly).
 */
export function hasAdminGroup(session: Session | null): boolean {
  return getUserGroups(session).includes(ADMIN_GROUP_NAME);
}

/** Strictly rejects unless ADMIN_GROUP_NAME is present — no partial match, no case-insensitivity, no fallback. */
export function AdminRoute({ isAdmin, children }: { isAdmin: boolean; children: ReactNode }) {
  if (!isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}
