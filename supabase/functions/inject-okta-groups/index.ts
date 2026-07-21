// Supabase Custom Access Token Hook.
// Okta drops the custom `groups` scope from the OIDC id_token in some configs,
// so we fetch group membership directly from the Okta Admin API at login time
// instead of relying on the token payload.

interface HookPayload {
  user_id: string;
  claims: Record<string, unknown> & {
    email?: string;
    app_metadata?: Record<string, unknown>;
  };
  authentication_method: string;
}

interface OktaGroup {
  profile: { name: string };
}

const OKTA_FETCH_TIMEOUT_MS = 5000;

Deno.serve(async (req: Request) => {
  const payload: HookPayload = await req.json();
  const { claims } = payload;
  const email = claims.email;

  if (!email) {
    return new Response(JSON.stringify({ claims }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  }

  try {
    const oktaDomain = Deno.env.get("OKTA_DOMAIN");
    const oktaApiToken = Deno.env.get("OKTA_API_TOKEN");

    if (!oktaDomain || !oktaApiToken) {
      throw new Error("missing OKTA_DOMAIN or OKTA_API_TOKEN");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), OKTA_FETCH_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch(
        `https://${oktaDomain}/api/v1/users/${encodeURIComponent(email)}/groups`,
        {
          headers: { Authorization: `SSWS ${oktaApiToken}` },
          signal: controller.signal,
        },
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new Error(`Okta API returned ${response.status}`);
    }

    const groups: OktaGroup[] = await response.json();
    const modifiedClaims = { ...claims };
    modifiedClaims.app_metadata = modifiedClaims.app_metadata || {};
    modifiedClaims.app_metadata.groups = groups.map((g) => g.profile.name);

    return new Response(JSON.stringify({ claims: modifiedClaims }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  } catch {
    return new Response(JSON.stringify({ claims }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  }
});
