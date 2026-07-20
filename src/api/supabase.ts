import { createClient } from "@supabase/supabase-js";
import { env } from "../config/env";

/**
 * Supabase is the OAuth broker for Okta now — it holds the client
 * ID/secret/issuer (configured in the dashboard, not here) and exchanges
 * the code with Okta itself, minting its own session. So this client needs
 * no custom accessToken callback: supabase-js manages its own session/token
 * refresh natively and attaches it to every request automatically.
 */
export const supabase = createClient(env.supabaseUrl, env.supabaseAnonKey);
