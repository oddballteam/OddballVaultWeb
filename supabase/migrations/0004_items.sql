-- Vault items. Content is bundled into one encrypted JSON envelope (title,
-- username, password, notes, custom fields, everything) rather than
-- per-column encryption, so title/search never touches Supabase in
-- plaintext — list/search happens client-side after bulk decrypt, the same
-- pattern used by Bitwarden/1Password.
create table public.items (
    id              uuid primary key default gen_random_uuid(),
    owner_user_id   text references public.user_directory(id) on delete cascade,
    owner_group_id  uuid references public.groups(id) on delete cascade,
    item_type       text not null check (item_type in
                        ('login', 'note', 'card', 'identity', 'ssh_key', 'api_credential')),
    is_favorite     boolean not null default false,
    is_deleted      boolean not null default false,
    nonce           text not null,
    ciphertext      text not null,   -- AES-256-GCM(Item Key, JSON envelope)
    key_version     int not null default 1,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    constraint items_exactly_one_owner check (
        (owner_user_id is not null) <> (owner_group_id is not null)
    )
);

-- The ACL: one row per (item, grantee). Possessing a row here at all implies
-- the ability to decrypt (wrapped_item_key unwraps with the grantee's own
-- key material); the `role` column is what Postgres enforces server-side.
create table public.item_keys (
    item_id         uuid not null references public.items(id) on delete cascade,
    grantee_type    text not null check (grantee_type in ('user', 'group')),
    grantee_id      text not null,   -- user_directory.id or groups.id (as text)
    wrapped_item_key text not null,  -- Item Key (32 bytes), RSA-OAEP-wrapped to grantee's public key
    role            text not null check (role in ('owner', 'edit_share', 'edit', 'view')),
    key_version     int not null,    -- must match items.key_version; stale rows are pre-rotation wraps
    granted_by      text references public.user_directory(id),
    granted_at      timestamptz not null default now(),
    primary key (item_id, grantee_type, grantee_id)
);

alter table public.items enable row level security;
alter table public.item_keys enable row level security;

-- A user's applicable grants = their own direct grants, plus any grant made
-- to a group they belong to.
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
    join public.group_memberships gm on gm.group_id::text = ik.grantee_id
    where ik.item_id = target_item_id
      and ik.grantee_type = 'group'
      and gm.user_id = public.current_user_id()
$$;

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

-- Item creation itself has no ACL yet to check against — the client inserts
-- the item row and its own 'owner' item_keys row in the same transaction,
-- so just require the caller to be creating it as themselves or a group they
-- belong to.
create policy "items_insert_self_or_own_group"
    on public.items for insert
    to authenticated
    with check (
        owner_user_id = public.current_user_id()
        or exists (
            select 1 from public.group_memberships gm
            where gm.group_id = items.owner_group_id
              and gm.user_id = public.current_user_id()
        )
    );

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

-- Granting/revoking access requires owner or edit_share on that item. The
-- very first grant (the creator's own 'owner' row) is inserted alongside the
-- item row and allowed because it names the caller as the grantee.
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

-- Role changes (e.g. downgrading someone from edit to view) — same
-- authority level as granting/revoking.
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

create index idx_items_type on public.items(item_type);
create index idx_items_deleted on public.items(is_deleted);
create index idx_item_keys_grantee on public.item_keys(grantee_type, grantee_id);
