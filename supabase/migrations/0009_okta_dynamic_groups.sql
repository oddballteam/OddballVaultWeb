-- Prep for moving Group Folder *visibility and admin-management* from the
-- app-managed group_memberships table to two Okta group claims directly,
-- without hardcoding any group name in application code:
--
--   okta_group_name        — standard members: can view the folder and
--                             its items (and create items in it).
--   okta_admin_group_name  — folder admins: everything a standard member
--                             can do, PLUS updating the folder row itself
--                             (rename, rotate keys, etc.). Being an admin
--                             does NOT require also being listed in
--                             okta_group_name — the two are independent
--                             columns, checked with OR for read access.
--
-- Neither column is hardcoded to a specific Okta group name in code — the
-- mapping lives entirely in these two columns, set per Group Folder.
--
-- READ BEFORE RELYING ON THIS — this is RLS-level prep, not a full cutover:
--
-- 1. group_memberships still exists and is still REQUIRED for the
--    cryptographic side of group sharing (crypto/groupKeys.ts): each
--    member's wrapped copy of the group's KEK. An Okta groups claim proves
--    membership/admin status for row-visibility and update purposes, but
--    it carries no key material, so it cannot substitute for the
--    wrapped-KEK mechanism. Concretely: being in either Okta group now
--    lets someone SELECT a group folder's row and (per below) its items
--    via RLS, but they still cannot DECRYPT the item content client-side
--    until groupService.addMember() has run for them and given them a
--    group_memberships row with their wrapped KEK. Zero-knowledge crypto
--    has no substitute for "someone with access has to wrap a key for
--    you" — a JWT claim alone can never grant decryption.
--
-- 2. item_keys' own policies (item_keys_select_visible, item_keys_insert_
--    sharers, item_keys_delete_sharers, item_keys_update_sharers, all in
--    0004_items.sql) still check group_memberships directly and are NOT
--    changed here. Only `groups` and `items` (the latter via
--    my_item_grant_roles(), which items' policies call) are in scope.
--
-- 3. This supersedes the first draft of this migration, which collapsed
--    "admin" and "member" into a single "any member can update" check.
--    That distinction is preserved here via okta_admin_group_name instead.

alter table public.groups
    add column if not exists okta_group_name text,
    add column if not exists okta_admin_group_name text;

comment on column public.groups.okta_group_name is
    'Okta group name granting standard (view/create-item) row-level access to this Group Folder via auth.jwt() -> app_metadata -> groups.';
comment on column public.groups.okta_admin_group_name is
    'Okta group name granting folder-admin (view + update-the-folder-row) row-level access to this Group Folder via auth.jwt() -> app_metadata -> groups.';

-- groups: select — standard members OR admins can view. Drops both the
-- original group_memberships-based policy and the single-column version
-- from the first draft of this migration, in case either was applied.
drop policy if exists "groups_select_members" on public.groups;
drop policy if exists "groups_select_okta_members" on public.groups;
create policy "groups_select_okta_members"
    on public.groups for select
    to authenticated
    using (
        (okta_group_name is not null and okta_group_name = any(public.jwt_groups()))
        or (okta_admin_group_name is not null and okta_admin_group_name = any(public.jwt_groups()))
    );

-- groups: update — admins only. Standard members (okta_group_name) cannot
-- update the folder row even though they can see it.
drop policy if exists "groups_update_admins" on public.groups;
drop policy if exists "groups_update_okta_members" on public.groups;
create policy "groups_update_okta_admins"
    on public.groups for update
    to authenticated
    using (
        okta_admin_group_name is not null
        and okta_admin_group_name = any(public.jwt_groups())
    );

-- Powers items_select_grantees / items_update_editors / items_delete_owners
-- (0004_items.sql) — those policies only call this function. Visibility of
-- group-owned items follows standard members OR admins, same as `groups`.
create or replace function public.my_item_grant_roles(target_item_id uuid)
returns setof text
language sql
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

-- items_insert_self_or_own_group (0004_items.sql) checked group_memberships
-- directly rather than through my_item_grant_roles() — same replacement,
-- for creating a new item owned by a Group Folder. Either group can create
-- items (member-level access); only admins can update/rename the folder
-- itself, per the groups_update_okta_admins policy above.
drop policy if exists "items_insert_self_or_own_group" on public.items;
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
