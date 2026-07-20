-- EMERGENCY FIX: group_memberships' own SELECT/INSERT/DELETE policies
-- (0003_groups.sql) are self-referential — each one's USING/WITH CHECK
-- clause queries group_memberships from a policy defined ON
-- group_memberships. Evaluating the policy requires reading rows from the
-- table, which re-triggers the same policy, which requires reading rows
-- again, and so on. Postgres detects this as infinite recursion (42P17)
-- rather than looping forever.
--
-- This trips on ANY query that touches group_memberships, however it gets
-- there — a direct select, item_keys' policies (which check
-- group_memberships in their own EXISTS clauses), or my_item_grant_roles()
-- (which joins it) — which is why it surfaced as "loading items on login"
-- rather than something that looked group-related.
--
-- Fix: two SECURITY DEFINER helper functions query group_memberships
-- directly, bypassing RLS for that one internal lookup. This works because
-- SECURITY DEFINER functions execute as their owner, and a table's owner
-- is exempt from its own RLS policies unless FORCE ROW LEVEL SECURITY is
-- set (it isn't, here). Policies call the helper instead of querying
-- group_memberships inline, which breaks the cycle.
--
-- All three original policies had the identical recursive shape — not
-- just the SELECT one that happened to trip first. INSERT and DELETE
-- would hit the same error the first time anyone tried to add or remove a
-- member, so all three are replaced here.

drop policy if exists "group_memberships_select_same_group" on public.group_memberships;
drop policy if exists "group_memberships_insert_admins" on public.group_memberships;
drop policy if exists "group_memberships_delete_admins" on public.group_memberships;

create or replace function public.is_group_member(target_group_id uuid, target_user_id text)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.group_memberships
    where group_id = target_group_id
      and user_id = target_user_id
  )
$$;

create or replace function public.is_group_admin(target_group_id uuid, target_user_id text)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.group_memberships
    where group_id = target_group_id
      and user_id = target_user_id
      and role = 'admin'
  )
$$;

revoke all on function public.is_group_member(uuid, text) from public;
revoke all on function public.is_group_admin(uuid, text) from public;
grant execute on function public.is_group_member(uuid, text) to authenticated;
grant execute on function public.is_group_admin(uuid, text) to authenticated;

-- user_id = current_user_id() is technically implied by is_group_member()
-- (a user's own row always proves their own membership), but both checks
-- are kept explicit per the original policy's intent — one is just a
-- cheap direct-row-ownership check, the other extends visibility to the
-- rest of the roster for groups you belong to.
create policy "group_memberships_select_same_group"
    on public.group_memberships for select
    to authenticated
    using (
        user_id = public.current_user_id()
        or public.is_group_member(group_id, public.current_user_id())
    );

create policy "group_memberships_insert_admins"
    on public.group_memberships for insert
    to authenticated
    with check (
        public.is_group_admin(group_id, public.current_user_id())
    );

create policy "group_memberships_delete_admins"
    on public.group_memberships for delete
    to authenticated
    using (
        public.is_group_admin(group_id, public.current_user_id())
    );
