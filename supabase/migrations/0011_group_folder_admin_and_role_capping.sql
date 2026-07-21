-- Group Folder creation + Okta-reconciled membership + owner/editor role capping.
--
-- Reverts 0009's okta_group_name/okta_admin_group_name detour: those columns were
-- never wired into any TS code (no UI, no types) and, more importantly, carry no
-- key material — someone satisfying an Okta claim still couldn't decrypt anything
-- without a group_memberships row wrapping the KEK for them. group_memberships is
-- back to being the sole source of truth for both "who's in the folder" and
-- "owner vs editor", kept in sync with Okta by a client-side reconciliation flow
-- (src/services/groupService.ts::reconcileGroupMembership, triggered when a folder
-- owner views the member list) rather than by trusting the JWT claim directly.
--
-- Drop order matters: policies referencing the doomed columns must go before the
-- columns themselves (Postgres blocks DROP COLUMN while a policy still depends on it).

drop policy if exists "groups_select_okta_members" on public.groups;
drop policy if exists "groups_update_okta_admins" on public.groups;
drop policy if exists "items_insert_self_or_own_group" on public.items;
drop policy if exists "items_select_grantees" on public.items;

alter table public.groups
    drop column if exists okta_group_name,
    drop column if exists okta_admin_group_name;

-- groups: select/update restored to group_memberships-based (reverting 0009).
create policy "groups_select_members"
    on public.groups for select
    to authenticated
    using (
        exists (
            select 1 from public.group_memberships gm
            where gm.group_id = groups.id and gm.user_id = public.current_user_id()
        )
    );

create policy "groups_update_admins"
    on public.groups for update
    to authenticated
    using (
        exists (
            select 1 from public.group_memberships gm
            where gm.group_id = groups.id and gm.user_id = public.current_user_id() and gm.role = 'admin'
        )
    );

-- groups: delete — folder owners only. No delete policy existed on `groups` before this.
create policy "groups_delete_admins"
    on public.groups for delete
    to authenticated
    using (
        exists (
            select 1 from public.group_memberships gm
            where gm.group_id = groups.id and gm.user_id = public.current_user_id() and gm.role = 'admin'
        )
    );

-- groups: insert — IT/Sec Admin only, creating a folder from the admin panel.
create policy "groups_insert_it_sec_admins"
    on public.groups for insert
    to authenticated
    with check ('IT/Sec Admin' = any(public.jwt_groups()));

-- groups/group_memberships: IT/Sec Admin can see every folder for the admin panel,
-- not just ones they personally belong to (groups_select_members above is membership-scoped).
create policy "groups_select_it_sec_admins"
    on public.groups for select
    to authenticated
    using ('IT/Sec Admin' = any(public.jwt_groups()));

create policy "group_memberships_select_it_sec_admins"
    on public.group_memberships for select
    to authenticated
    using ('IT/Sec Admin' = any(public.jwt_groups()));

-- group_memberships: role elevation (member -> admin) is an IT/Sec-Admin-only, admin-panel
-- action — folder owners themselves do not get a self-service update grant here.
create policy "group_memberships_update_it_sec_admins"
    on public.group_memberships for update
    to authenticated
    using ('IT/Sec Admin' = any(public.jwt_groups()))
    with check ('IT/Sec Admin' = any(public.jwt_groups()));

-- group_memberships: insert. Existing admin-adds-a-member path preserved, plus a
-- chicken-and-egg carve-out (same shape as 0010's items_select_grantees fix) for a
-- brand-new group's very first row — restricted to "IT/Sec Admin AND zero existing
-- rows for this group" so it can't be used to self-join an existing group as fake admin.
drop policy if exists "group_memberships_insert_admins" on public.group_memberships;
create policy "group_memberships_insert_admins"
    on public.group_memberships for insert
    to authenticated
    with check (
        exists (
            select 1 from public.group_memberships admin_row
            where admin_row.group_id = group_memberships.group_id
              and admin_row.user_id = public.current_user_id()
              and admin_row.role = 'admin'
        )
        or (
            'IT/Sec Admin' = any(public.jwt_groups())
            and not exists (
                select 1 from public.group_memberships existing
                where existing.group_id = group_memberships.group_id
            )
        )
    );

-- items: insert/select restored to group_memberships-based (reverting 0009's detour),
-- preserving 0010's "visible immediately on creation" RETURNING fix on items_select_grantees.
create policy "items_insert_self_or_own_group"
    on public.items for insert
    to authenticated
    with check (
        owner_user_id = public.current_user_id()
        or exists (
            select 1 from public.group_memberships gm
            where gm.group_id = items.owner_group_id and gm.user_id = public.current_user_id()
        )
    );

create policy "items_select_grantees"
    on public.items for select
    to authenticated
    using (
        exists (select 1 from public.my_item_grant_roles(items.id))
        or owner_user_id = public.current_user_id()
        or exists (
            select 1 from public.group_memberships gm
            where gm.group_id = items.owner_group_id and gm.user_id = public.current_user_id()
        )
    );

-- THE role-capping fix: group_memberships.role is now the sole owner/editor source of
-- truth for group-owned items. 'admin' -> stored item_keys.role (owner, since group
-- grants are always created with role='owner'). 'member' -> capped to 'edit' regardless
-- of stored role. Stays SECURITY DEFINER (required since 0008c to avoid the
-- item_keys-recursion bug) — every items/item_keys policy already funnels through this
-- one function, so the owner/editor distinction now applies everywhere with no other
-- RLS changes needed.
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
    select case when gm.role = 'admin' then ik.role else 'edit' end
    from public.item_keys ik
    join public.group_memberships gm on gm.group_id::text = ik.grantee_id
    where ik.item_id = target_item_id
      and ik.grantee_type = 'group'
      and gm.user_id = public.current_user_id()
$$;

-- New admin-panel actions get their own audit trail entries alongside the existing ones.
alter table public.audit_log drop constraint audit_log_event_type_check;
alter table public.audit_log add constraint audit_log_event_type_check check (event_type in (
    'unlock', 'lock', 'failed_unlock',
    'item_created', 'item_viewed', 'item_edited', 'item_deleted',
    'item_shared', 'item_unshared', 'role_changed',
    'item_key_rotated', 'group_key_rotated',
    'export', 'import', 'password_changed', 'vault_reset',
    'group_folder_created', 'group_folder_renamed', 'group_folder_deleted'
));
