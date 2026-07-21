// Lets the admin panel search Okta groups by name instead of requiring the
// admin to manually look up and paste a raw Okta group ID when creating a
// Group Folder (src/views/AdminDashboardView.tsx). Deployed WITHOUT
// --no-verify-jwt — a normal authenticated endpoint, not an auth hook.
//
// IT/Sec Admin only: creating a Group Folder is already restricted to that
// group via RLS (groups_insert_it_sec_admins), so browsing Okta's group list
// is gated the same way rather than opened to every authenticated user.

const OKTA_FETCH_TIMEOUT_MS = 5000;

interface OktaGroup {
  id: string;
  profile: { name?: string };
}

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

Deno.serve(async (req: Request) => {
  try {
    const authHeader = req.headers.get("Authorization");
    const claims = decodeJwtClaims(authHeader);
    const callerGroups = (claims?.app_metadata as { groups?: unknown } | undefined)?.groups;
    const isItSecAdmin = Array.isArray(callerGroups) && callerGroups.includes("IT/Sec Admin");

    if (!authHeader || !isItSecAdmin) {
      return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });
    }

    const { query } = await req.json();
    if (!query || typeof query !== "string" || query.trim().length < 2) {
      return new Response(JSON.stringify({ groups: [] }), {
        headers: { "Content-Type": "application/json" },
        status: 200,
      });
    }

    const oktaDomain = Deno.env.get("OKTA_DOMAIN");
    const oktaApiToken = Deno.env.get("OKTA_API_TOKEN");
    if (!oktaDomain || !oktaApiToken) {
      return new Response(JSON.stringify({ error: "Okta integration not configured" }), { status: 200 });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), OKTA_FETCH_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetch(
        `https://${oktaDomain}/api/v1/groups?q=${encodeURIComponent(query.trim())}&limit=20`,
        { headers: { Authorization: `SSWS ${oktaApiToken}` }, signal: controller.signal },
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Okta API returned ${response.status}: ${errorText}`);
    }

    const oktaGroups: OktaGroup[] = await response.json();
    const groups = oktaGroups
      .filter((g) => g.profile.name)
      .map((g) => ({ id: g.id, name: g.profile.name as string }));

    return new Response(JSON.stringify({ groups }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  } catch (err) {
    console.error("search-okta-groups: failed", err);
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Unknown error" }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  }
});
