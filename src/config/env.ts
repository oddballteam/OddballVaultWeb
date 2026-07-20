/**
 * Warns rather than throws on a missing var so the app shell (login screen,
 * layout, etc.) still renders during local preview/dev without real Okta or
 * Supabase credentials configured yet — actual sign-in/data calls will fail
 * against the placeholder value, but that failure is contained to those
 * calls instead of blanking the whole page at import time.
 */
function required(name: string, placeholder: string): string {
  const value = import.meta.env[name];
  if (!value) {
    console.warn(`Missing env var ${name} — using placeholder. Set it in .env.local before real use.`);
    return placeholder;
  }
  return value;
}

export const env = {
  // No VITE_OKTA_* vars — Supabase is the OAuth broker for Okta now (its
  // dashboard holds the client ID/secret/issuer), so the frontend never
  // talks to Okta directly and doesn't need to know any of that.
  supabaseUrl: required("VITE_SUPABASE_URL", "https://placeholder.supabase.invalid"),
  supabaseAnonKey: required("VITE_SUPABASE_ANON_KEY", "placeholder-anon-key"),
  /**
   * Dev-only escape hatch for UI/layout review without a real Okta tenant —
   * gated on Vite's DEV flag too, so a stray "true" in a shipped .env can't
   * turn this on in a production build.
   */
  mockAuthEnabled: import.meta.env.DEV && import.meta.env.VITE_MOCK_AUTH === "true",
  /** Dev-only: puts the mock user in the "IT/Sec Admin" Okta group so /admin can be previewed without a real Okta tenant. */
  mockAdminEnabled: import.meta.env.DEV && import.meta.env.VITE_MOCK_ADMIN === "true",
};
