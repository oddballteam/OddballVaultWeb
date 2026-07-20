-- Okta issues non-UUID subject identifiers (e.g. "00u1a2b3c4d5e6f7g8h9"), so
-- auth.uid() (which casts the JWT 'sub' claim to uuid) cannot be used here —
-- it would throw on every request. Every policy below compares against this
-- text-typed helper instead.
create or replace function public.current_user_id()
returns text
language sql
stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::json ->> 'sub', '')
$$;
