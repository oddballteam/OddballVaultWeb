-- External one-time share links: lets an internal user hand a record to someone
-- outside the org with no Okta identity, no Supabase account, and no access to
-- the app itself. The encryption key never reaches this table or any server —
-- it lives only in the share URL's fragment (#...), which browsers never send
-- over the network. This table and the RPC below only ever see ciphertext.
--
-- No Edge Function, no pg_cron: the claim RPC is the entire anonymous-reachable
-- surface, and it opportunistically sweeps expired/burned rows on every call so
-- nothing depends on a scheduled job existing.

create table public.external_shares (
    id          uuid primary key default gen_random_uuid(),
    created_by  text not null references public.user_directory(id) on delete cascade,
    nonce       text not null,
    ciphertext  text not null,
    created_at  timestamptz not null default now(),
    expires_at  timestamptz not null,
    burned_at   timestamptz
);

alter table public.external_shares enable row level security;

-- Creator can insert/view/revoke their own links (for the "active links" list in Settings).
-- anon gets NO policy here at all — default deny. The only anon-reachable surface is the
-- claim_external_share() RPC below.
create policy "external_shares_insert_self"
    on public.external_shares for insert
    to authenticated
    with check (created_by = public.current_user_id());

create policy "external_shares_select_self"
    on public.external_shares for select
    to authenticated
    using (created_by = public.current_user_id());

create policy "external_shares_delete_self"
    on public.external_shares for delete
    to authenticated
    using (created_by = public.current_user_id());

-- The one narrow, anonymous-reachable operation: atomically claim (burn) a share
-- by id. SECURITY DEFINER bypasses RLS internally (same justification as
-- nuke_user_vault: the anon role has no table grants at all otherwise), but the
-- function body IS the entire attack surface — it does nothing but this one
-- compare-and-set, so there is nothing else for an anonymous caller to reach.
create or replace function public.claim_external_share(share_id uuid)
returns table (nonce text, ciphertext text)
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.external_shares where expires_at < now() or burned_at is not null;

  return query
    update public.external_shares es
    set burned_at = now()
    where es.id = share_id and es.burned_at is null and es.expires_at > now()
    returning es.nonce, es.ciphertext;
end;
$$;

revoke all on function public.claim_external_share(uuid) from public;
grant execute on function public.claim_external_share(uuid) to anon, authenticated;

alter table public.audit_log drop constraint audit_log_event_type_check;
alter table public.audit_log add constraint audit_log_event_type_check check (event_type in (
    'unlock', 'lock', 'failed_unlock',
    'item_created', 'item_viewed', 'item_edited', 'item_deleted',
    'item_shared', 'item_unshared', 'role_changed',
    'item_key_rotated', 'group_key_rotated',
    'export', 'import', 'password_changed', 'vault_reset',
    'group_folder_created', 'group_folder_renamed', 'group_folder_deleted',
    'external_share_created'
));
