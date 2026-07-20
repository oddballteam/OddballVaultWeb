-- EMERGENCY FIX #2: my_item_grant_roles() (0004_items.sql, later replaced
-- by 0009's two-column version) is a plain SECURITY INVOKER function that
-- queries item_keys internally. All four of item_keys' own policies
-- (select/insert/delete/update) call this function to check "does the
-- caller have owner/edit_share on this item" — but because the function
-- runs as invoker, its internal item_keys query is itself subject to
-- item_keys' RLS, i.e. the very policies that just called it:
--
--   items policy -> my_item_grant_roles() -> reads item_keys
--     -> item_keys policy -> my_item_grant_roles() -> reads item_keys
--       -> item_keys policy -> ... (forever)
--
-- Unlike a direct "policy queries its own table" cycle (which Postgres
-- detects immediately as 42P17), this one is mediated through a function
-- call boundary, so Postgres doesn't catch it as policy recursion — it
-- just keeps recursing until it blows the real call stack (54001).
--
-- Fix: my_item_grant_roles() becomes SECURITY DEFINER, so its internal
-- item_keys read bypasses RLS entirely (running as the function's owner,
-- which is exempt from RLS on tables it owns unless FORCE ROW LEVEL
-- SECURITY is set — it isn't). That breaks the cycle at its one true
-- source: every other policy in this script is being dropped and
-- recreated with IDENTICAL logic to what's currently live, not because
-- their own text was wrong, but so this script is a complete, standalone,
-- auditable statement of every items/item_keys policy after the fix —
-- given this is the second recursion bug in a row, guessing "just the
-- function" is enough without re-asserting everything explicitly wasn't
-- a chance worth taking.
--
-- current_setting()/auth.jwt()-based checks (current_user_id(),
-- jwt_groups()) still correctly reflect the ACTUAL calling session inside
-- a SECURITY DEFINER function — that setting is session-scoped, not
-- role-privilege-scoped, so this does not weaken who the function
-- computes grants for, only which role's RLS applies to its internal read.

drop policy if exists "items_select_grantees" on public.items;
drop policy if exists "items_update_editors" on public.items;
drop policy if exists "items_delete_owners" on public.items;
drop policy if exists "items_insert_self_or_own_group" on public.items;

drop policy if exists "item_keys_select_visible" on public.item_keys;
drop policy if exists "item_keys_insert_sharers" on public.item_keys;
drop policy if exists "item_keys_delete_sharers" on public.item_keys;
drop policy if exists "item_keys_update_sharers" on public.item_keys;

-- The actual fix. Logic is unchanged from 0009's version (grants visibility
-- to a group's item_keys row if the caller is in either okta_group_name or
-- okta_admin_group_name) — only the SECURITY DEFINER + search_path lines
-- are new.
create or replace function public.my_item_grant_roles(target_item_id uuid)
returns setof text
language sql
security definer
set search_path = public
stable
as $$
    select role from public.item_keys
    where item_id = target_item_id
      and grantee_type = 'user'
      and grantee_id = public.current_user_id()
    union
    select ik.role from public.item_keys ik
    join public.groups g on g.id::text = ik.grantee_id
    where ik.item_id = target_item_id
      and ik.grantee_type = 'group'
      and (
        (g.okta_group_name is not null and g.okta_group_name = any(public.jwt_groups()))
        or (g.okta_admin_group_name is not null and g.okta_admin_group_name = any(public.jwt_groups()))
      )
$$;

-- items: unchanged logic, re-asserted.
create policy "items_select_grantees"
    on public.items for select
    to authenticated
    using (exists (select 1 from public.my_item_grant_roles(items.id)));

create policy "items_update_editors"
    on public.items for update
    to authenticated
    using (
        exists (
            select 1 from public.my_item_grant_roles(items.id) r
            where r in ('owner', 'edit_share', 'edit')
        )
    );

create policy "items_delete_owners"
    on public.items for delete
    to authenticated
    using (
        exists (
            select 1 from public.my_item_grant_roles(items.id) r
            where r = 'owner'
        )
    );

create policy "items_insert_self_or_own_group"
    on public.items for insert
    to authenticated
    with check (
        owner_user_id = public.current_user_id()
        or exists (
            select 1 from public.groups g
            where g.id = items.owner_group_id
              and (
                (g.okta_group_name is not null and g.okta_group_name = any(public.jwt_groups()))
                or (g.okta_admin_group_name is not null and g.okta_admin_group_name = any(public.jwt_groups()))
              )
        )
    );

-- item_keys: unchanged logic, re-asserted. The group_memberships subquery
-- here now runs cleanly since 0008b already fixed group_memberships' own
-- policies to not be recursive; the my_item_grant_roles() calls now run
-- cleanly since that function is SECURITY DEFINER as of this migration.
create policy "item_keys_select_visible"
    on public.item_keys for select
    to authenticated
    using (
        (grantee_type = 'user' and grantee_id = public.current_user_id())
        or (grantee_type = 'group' and exists (
            select 1 from public.group_memberships gm
            where gm.group_id::text = item_keys.grantee_id
              and gm.user_id = public.current_user_id()
        ))
        or exists (
            select 1 from public.my_item_grant_roles(item_keys.item_id) r
            where r in ('owner', 'edit_share')
        )
    );

create policy "item_keys_insert_sharers"
    on public.item_keys for insert
    to authenticated
    with check (
        (grantee_type = 'user' and grantee_id = public.current_user_id())
        or exists (
            select 1 from public.my_item_grant_roles(item_keys.item_id) r
            where r in ('owner', 'edit_share')
        )
    );

create policy "item_keys_delete_sharers"
    on public.item_keys for delete
    to authenticated
    using (
        exists (
            select 1 from public.my_item_grant_roles(item_keys.item_id) r
            where r in ('owner', 'edit_share')
        )
    );

create policy "item_keys_update_sharers"
    on public.item_keys for update
    to authenticated
    using (
        exists (
            select 1 from public.my_item_grant_roles(item_keys.item_id) r
            where r in ('owner', 'edit_share')
        )
    )
    with check (
        exists (
            select 1 from public.my_item_grant_roles(item_keys.item_id) r
            where r in ('owner', 'edit_share')
        )
    );
