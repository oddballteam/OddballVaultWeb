-- Bug: creating ANY item (personal or group) failed with "new row violates
-- row-level security policy for table items" on every insert, unrelated to
-- Okta groups. Root cause: the client does items.insert(...).select().single()
-- (vaultService.ts createItem), which PostgREST implements as
-- INSERT ... RETURNING *. RETURNING requires the SELECT policy to permit
-- reading the new row, but items_select_grantees only grants visibility via
-- an item_keys row -- and the item_keys "owner" grant is created in a
-- SEPARATE, later insert (right after this one returns). So at the moment
-- RETURNING is evaluated, no grant exists yet for the item the caller is
-- literally in the middle of creating.
--
-- Fix: let items_select_grantees also recognize the same
-- "creating this as yourself / your own group" condition that
-- items_insert_self_or_own_group already checks, so the row is visible
-- immediately on creation, before any item_keys row exists.

drop policy if exists "items_select_grantees" on public.items;
create policy "items_select_grantees"
    on public.items for select
    to authenticated
    using (
        exists (select 1 from public.my_item_grant_roles(items.id))
        or owner_user_id = public.current_user_id()
        or exists (
            select 1 from public.groups g
            where g.id = items.owner_group_id
              and (
                (g.okta_group_name is not null and g.okta_group_name = any(public.jwt_groups()))
                or (g.okta_admin_group_name is not null and g.okta_admin_group_name = any(public.jwt_groups()))
              )
        )
    );
