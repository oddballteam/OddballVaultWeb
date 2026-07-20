-- Group Folders (e.g. "Engineering", "Finance"), mapped 1:1 to an Okta group.
-- Each group has its own RSA-OAEP-3072 keypair so items can be shared with
-- "everyone in this group" via a single wrap, rather than one wrap per member.
--
-- Tables are created first (in dependency order), RLS is enabled on both,
-- and every policy comes last — groups' policies reference
-- group_memberships in their USING clause, so group_memberships must exist
-- as a relation before any policy mentioning it is created.

create table public.groups (
    id                      uuid primary key default gen_random_uuid(),
    name                    text not null,
    okta_group_id           text not null unique,
    public_key              text not null,
    encrypted_private_key   text not null,   -- AES-256-GCM(Group KEK, PKCS8 private key)
    private_key_nonce       text not null,
    key_version             int not null default 1,   -- bumped on member-removal re-key
    created_at              timestamptz not null default now()
);

-- Mirrors Okta group membership rather than trusting the JWT's groups claim
-- live: Okta's groups claim can be size-filtered and a still-valid token
-- won't reflect a mid-session removal. A reconciliation job keeps this in
-- sync against Okta's Groups API.
create table public.group_memberships (
    group_id            uuid not null references public.groups(id) on delete cascade,
    user_id              text not null references public.user_directory(id) on delete cascade,
    wrapped_group_kek    text not null,   -- 32-byte Group KEK, RSA-OAEP-wrapped to this member's public key
    role                 text not null default 'member' check (role in ('member', 'admin')),
    added_at             timestamptz not null default now(),
    primary key (group_id, user_id)
);

alter table public.groups enable row level security;
alter table public.group_memberships enable row level security;

create policy "groups_select_members"
    on public.groups for select
    to authenticated
    using (
        exists (
            select 1 from public.group_memberships gm
            where gm.group_id = groups.id
              and gm.user_id = public.current_user_id()
        )
    );

-- Group creation/provisioning is an administrative action tied to Okta group
-- lifecycle, not end-user self-service — restricted to group admins (and, for
-- the very first admin of a brand-new group, a provisioning script running
-- with the service role, which bypasses RLS entirely).
create policy "groups_update_admins"
    on public.groups for update
    to authenticated
    using (
        exists (
            select 1 from public.group_memberships gm
            where gm.group_id = groups.id
              and gm.user_id = public.current_user_id()
              and gm.role = 'admin'
        )
    );

create policy "group_memberships_select_same_group"
    on public.group_memberships for select
    to authenticated
    using (
        user_id = public.current_user_id()
        or exists (
            select 1 from public.group_memberships self
            where self.group_id = group_memberships.group_id
              and self.user_id = public.current_user_id()
        )
    );

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
    );

create policy "group_memberships_delete_admins"
    on public.group_memberships for delete
    to authenticated
    using (
        exists (
            select 1 from public.group_memberships admin_row
            where admin_row.group_id = group_memberships.group_id
              and admin_row.user_id = public.current_user_id()
              and admin_row.role = 'admin'
        )
    );

create index idx_group_memberships_user on public.group_memberships(user_id);
