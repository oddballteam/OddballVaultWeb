// Returns the live Okta group membership (emails) for a Group Folder, so the
// client can reconcile group_memberships against it (src/services/groupService.ts
// ::reconcileGroupMembership). Deployed WITHOUT --no-verify-jwt (unlike
// inject-okta-groups) — this is a normal authenticated endpoint, not an auth hook.
//
// The caller only ever supplies the internal groups.id (a UUID), never Okta's own
// group ID — this function looks that up server-side itself, so a caller can't
// probe another folder's Okta group membership by guessing/passing a different ID.

import { createClient } from "jsr:@supabase/supabase-js@2";

interface OktaUser {
  profile: { email?: string; login?: string };
}

const OKTA_FETCH_TIMEOUT_MS = 5000;
const MAX_PAGES = 10; // ponytail: raise if a real group exceeds ~2000 members (Okta pages at up to 200/req here)

function decodeJwtClaims(authHeader: string | null): Record<string, unknown> | null {
  const token = authHeader?.replace(/^Bearer\s+/i, "");
  const segment = token?.split(".")[1];
  if (!segment) return null;
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  try {
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

async function fetchAllOktaGroupMembers(oktaDomain: string, oktaApiToken: string, oktaGroupId: string): Promise<string[]> {
  const emails: string[] = [];
  let url: string | null = `https://${oktaDomain}/api/v1/groups/${encodeURIComponent(oktaGroupId)}/users?limit=200`;

  for (let page = 0; url && page < MAX_PAGES; page++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), OKTA_FETCH_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetch(url, {
        headers: { Authorization: `SSWS ${oktaApiToken}` },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Okta API returned ${response.status}: ${errorText}`);
    }

    const users: OktaUser[] = await response.json();
    for (const u of users) {
      const email = u.profile.email ?? u.profile.login;
      if (email) emails.push(email);
    }

    const linkHeader = response.headers.get("link") ?? "";
    const nextMatch = linkHeader.split(",").find((part) => part.includes('rel="next"'));
    url = nextMatch ? nextMatch.slice(nextMatch.indexOf("<") + 1, nextMatch.indexOf(">")) : null;
  }

  return emails;
}

Deno.serve(async (req: Request) => {
  try {
    const authHeader = req.headers.get("Authorization");
    const claims = decodeJwtClaims(authHeader);
    const callerId = claims?.sub as string | undefined;
    const callerGroups = (claims?.app_metadata as { groups?: unknown } | undefined)?.groups;
    const isItSecAdmin = Array.isArray(callerGroups) && callerGroups.includes("IT/Sec Admin");

    if (!authHeader || !callerId) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    const { groupId } = await req.json();
    if (!groupId) {
      return new Response(JSON.stringify({ error: "Missing groupId" }), { status: 400 });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    // JWT-scoped client (forwards the caller's own token) — RLS applies, no service role needed.
    const supabase = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: group, error: groupError } = await supabase
      .from("groups")
      .select("okta_group_id")
      .eq("id", groupId)
      .single();
    if (groupError || !group) {
      return new Response(JSON.stringify({ error: "Group folder not found" }), { status: 404 });
    }

    if (!isItSecAdmin) {
      const { data: membership } = await supabase
        .from("group_memberships")
        .select("role")
        .eq("group_id", groupId)
        .eq("user_id", callerId)
        .eq("role", "admin")
        .maybeSingle();
      if (!membership) {
        return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });
      }
    }

    const oktaDomain = Deno.env.get("OKTA_DOMAIN");
    const oktaApiToken = Deno.env.get("OKTA_API_TOKEN");
    if (!oktaDomain || !oktaApiToken) {
      return new Response(JSON.stringify({ error: "Okta integration not configured" }), { status: 200 });
    }

    const emails = await fetchAllOktaGroupMembers(oktaDomain, oktaApiToken, group.okta_group_id);
    return new Response(JSON.stringify({ emails }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  } catch (err) {
    console.error("group-okta-members: failed", err);
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Unknown error" }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  }
});
