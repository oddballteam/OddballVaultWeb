-- Enterprise IT/Security admin dashboard support.
--
-- IMPORTANT — this table is NOT the same as the existing `audit_log` table
-- (0005_attachments_and_audit.sql). `audit_log` is a per-user security event
-- log (unlock/lock/item_created/etc.) that each user can only read their own
-- rows of. `audit_logs` (plural) below is a separate, IT/Sec-Admin-only
-- enterprise trail of sharing/ownership/wipe actions across ALL users.
--
-- `item_name` here is a plaintext snapshot written by the client at the
-- moment of a share/transfer/wipe action — the client already had to decrypt
-- the item to perform that action. The `items` table itself is untouched:
-- titles stay AES-256-GCM-encrypted like every other field, for every item
-- that is never shared. This preserves zero-knowledge at rest while still
-- giving IT/Sec a plaintext trail of the specific, deliberate actions an
-- admin needs to see — the same approach zero-knowledge products like
-- 1Password Business and Bitwarden Business use for their admin activity
-- logs.
create table public.audit_logs (
    id           uuid primary key default gen_random_uuid(),
    "timestamp"  timestamptz not null default now(),
    action       text not null check (action in ('item_shared', 'ownership_transferred', 'vault_wiped')),
    actor_email  text not null,
    target_email text not null,
    item_name    text not null
);

alter table public.audit_logs enable row level security;

-- Returns the Okta 'groups' claim as a text[], or '{}' if absent — used to
-- gate both this table's RLS and the nuke_user_vault() RPC below on the
-- same "IT/Sec Admin" group membership the client checks for /admin.
create or replace function public.jwt_groups()
returns text[]
language sql
stable
as $$
  select coalesce(
    (
      select array_agg(value #>> '{}')
      from jsonb_array_elements(
        nullif(current_setting('request.jwt.claims', true)::jsonb -> 'groups', 'null'::jsonb)
      )
    ),
    array[]::text[]
  )
$$;

create or replace function public.current_user_email()
returns text
language sql
stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::json ->> 'email', '')
$$;

create policy "audit_logs_select_it_sec_admins"
    on public.audit_logs for select
    to authenticated
    using ('IT/Sec Admin' = any(public.jwt_groups()));

-- Any authenticated user can write an entry (they're the one sharing/
-- transferring), but only attributed to themselves as actor — they can't
-- forge someone else's entry.
create policy "audit_logs_insert_self_as_actor"
    on public.audit_logs for insert
    to authenticated
    with check (actor_email = public.current_user_email());

create index idx_audit_logs_timestamp on public.audit_logs("timestamp" desc);

-- The kill switch. SECURITY DEFINER is required to delete another user's
-- rows at all (RLS on `items` would otherwise block it) — which is exactly
-- why the admin-group check is enforced INSIDE the function body, not left
-- to RLS. Without that internal check, security definer would let any
-- authenticated caller wipe any other user's vault.
create or replace function public.nuke_user_vault(target_user_id text default null, target_email text default null)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  resolved_user_id text;
  resolved_email text;
  deleted_count integer;
begin
  if not ('IT/Sec Admin' = any(public.jwt_groups())) then
    raise exception 'Access denied: nuke_user_vault requires IT/Sec Admin group membership';
  end if;

  if target_user_id is not null then
    resolved_user_id := target_user_id;
    select email into resolved_email from public.user_directory where id = target_user_id;
  elsif target_email is not null then
    select id, email into resolved_user_id, resolved_email from public.user_directory where email = target_email;
    if resolved_user_id is null then
      raise exception 'No user found with email %', target_email;
    end if;
  else
    raise exception 'Must provide target_user_id or target_email';
  end if;

  delete from public.items where owner_user_id = resolved_user_id;
  get diagnostics deleted_count = row_count;

  insert into public.audit_logs (action, actor_email, target_email, item_name)
  values (
    'vault_wiped',
    coalesce(public.current_user_email(), 'unknown'),
    coalesce(resolved_email, resolved_user_id),
    deleted_count || ' item(s) deleted'
  );

  return deleted_count;
end;
$$;

revoke all on function public.nuke_user_vault(text, text) from public;
grant execute on function public.nuke_user_vault(text, text) to authenticated;
