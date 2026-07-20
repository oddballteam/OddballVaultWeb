/**
 * Supabase is the OAuth broker for Okta — the frontend only ever talks to
 * Supabase. Its dashboard (Authentication → Providers) holds the Okta
 * client ID/secret/issuer and does the actual token exchange server-side;
 * signInWithOAuth() just kicks off the redirect.
 *
 * OKTA_PROVIDER_ID must match the exact provider ID registered there — if
 * you named it something other than "custom:okta", update this constant.
 *
 * No manual /callback route is needed: supabase-js defaults to the
 * implicit OAuth flow with detectSessionInUrl on, so it auto-parses the
 * access token out of the URL fragment when the browser lands back on this
 * app after Okta redirects through Supabase — AuthProvider's
 * onAuthStateChange listener picks it up from there.
 */
import type { Session, User } from "@supabase/supabase-js";
import { supabase } from "../api/supabase";
import { env } from "../config/env";

const OKTA_PROVIDER_ID = "custom:okta" as const;

/**
 * VITE_MOCK_AUTH=true injects a fake authenticated session instead of
 * calling Supabase at all — for reviewing the vault UI/layout without a
 * configured Supabase/Okta integration. Never wired to anything Supabase
 * trusts beyond a placeholder anon key, so it can't grant real data access.
 */
let mockSession: Session | null = null;

function createMockUser(): User {
  const now = new Date().toISOString();
  return {
    id: "mock-user-0001",
    aud: "authenticated",
    app_metadata: { groups: env.mockAdminEnabled ? ["IT/Sec Admin"] : [] },
    user_metadata: {},
    email: "demo@oddball.io",
    created_at: now,
  };
}

function createMockSession(): Session {
  return {
    access_token: "mock-access-token",
    refresh_token: "mock-refresh-token",
    expires_in: 3600,
    token_type: "bearer",
    user: createMockUser(),
  };
}

export async function login(): Promise<void> {
  if (env.mockAuthEnabled) {
    mockSession = createMockSession();
    return;
  }
  // Explicit scopes — without these Supabase can fail to get an email back
  // from the provider ("Error getting user email from external provider"),
  // since Okta only returns email/profile claims if actually requested.
  const { error } = await supabase.auth.signInWithOAuth({
    provider: OKTA_PROVIDER_ID,
    options: { scopes: "openid email profile" },
  });
  if (error) throw error;
}

export async function logout(): Promise<void> {
  if (env.mockAuthEnabled) {
    mockSession = null;
    return;
  }
  await supabase.auth.signOut();
}

export async function getCurrentSession(): Promise<Session | null> {
  if (env.mockAuthEnabled) return mockSession;
  const { data } = await supabase.auth.getSession();
  return data.session;
}
