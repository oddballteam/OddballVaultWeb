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

    console.log("inject-okta-groups: fetching Okta groups for email:", email);

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

    console.log("inject-okta-groups: Okta API responded with status:", response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("inject-okta-groups: Okta API error response:", errorText);
      throw new Error(`Okta API returned ${response.status}`);
    }

    const groups: OktaGroup[] = await response.json();
    const modifiedClaims = { ...claims };
    modifiedClaims.app_metadata = modifiedClaims.app_metadata || {};
    modifiedClaims.app_metadata.groups = groups.map((g) => g.profile.name);

    console.log("inject-okta-groups: injected groups:", modifiedClaims.app_metadata.groups);

    return new Response(JSON.stringify({ claims: modifiedClaims }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  } catch (err) {
    console.error("inject-okta-groups: failed to fetch Okta groups", err);
    return new Response(JSON.stringify({ claims }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  }
});
