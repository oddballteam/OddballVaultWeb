-- Supabase now brokers the Okta OAuth handshake itself (a "Custom OAuth
-- provider" registered in Authentication → Providers), rather than the
-- frontend running its own PKCE flow and handing Supabase a raw Okta JWT.
-- That means the JWT PostgREST sees on every request is SUPABASE's own
-- minted session token, not Okta's — and Supabase's JWT does not
-- automatically carry Okta's custom `groups` claim just because Okta
-- returned it during the OAuth handshake.
--
-- The fix is a Custom Access Token Hook: a function Supabase Auth calls
-- every time it mints a session JWT, letting us inject extra claims. This
-- one copies whatever "groups" Okta returned (stored by Supabase in
-- auth.identities.identity_data, the raw provider profile) into the
-- token's app_metadata claim, which IS included in Supabase's JWT by
-- default.
--
-- MANUAL STEP REQUIRED — this cannot be done from SQL:
--   Supabase Dashboard → Authentication → Hooks → "Customize Access Token
--   (JWT) Claims hook" → select public.custom_access_token_hook.
--
-- ALSO VERIFY — this is the part most likely to need adjustment for your
-- specific setup:
--   1. That your Okta app / auth server actually issues a "groups" claim
--      (requires a Groups Claim configured in Okta and the right scope
--      requested by the Supabase OAuth provider config).
--   2. That auth.identities.identity_data actually contains it — check via
--      SQL: select identity_data from auth.identities where user_id = '<uuid>';
--   3. That a real login's JWT ends up with app_metadata.groups set as
--      expected — decode session.access_token (e.g. at jwt.io) after
--      signing in to confirm before relying on /admin access.
-- If any of the above doesn't hold, admin-gated features (this hook,
-- audit_logs RLS, nuke_user_vault) will see an empty group list for
-- everyone rather than failing loudly.

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
as $$
declare
  claims jsonb;
  provider_groups jsonb;
begin
  claims := event -> 'claims';

  select identity_data -> 'groups'
  into provider_groups
  from auth.identities
  where user_id = (event ->> 'user_id')::uuid
  order by last_sign_in_at desc nulls last
  limit 1;

  if provider_groups is not null then
    claims := jsonb_set(claims, '{app_metadata,groups}', provider_groups, true);
  end if;

  event := jsonb_set(event, '{claims}', claims);
  return event;
end;
$$;

revoke all on function public.custom_access_token_hook(jsonb) from authenticated, anon, public;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;

-- jwt_groups() now reads the claim from where Supabase's JWT actually puts
-- it — nested under app_metadata, not top-level like Okta's raw id_token.
create or replace function public.jwt_groups()
returns text[]
language sql
stable
as $$
  select coalesce(
    (
      select array_agg(value #>> '{}')
      from jsonb_array_elements(
        nullif(
          current_setting('request.jwt.claims', true)::jsonb -> 'app_metadata' -> 'groups',
          'null'::jsonb
        )
      )
    ),
    array[]::text[]
  )
$$;
