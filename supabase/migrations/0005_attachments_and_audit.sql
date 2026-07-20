-- Attachments share the parent item's Item Key — no separate wrapping system
-- needed. Encrypted bytes live in Supabase Storage (see 0006); this row is
-- metadata only.
create table public.attachments (
    id                  uuid primary key default gen_random_uuid(),
    item_id             uuid not null references public.items(id) on delete cascade,
    nonce               text not null,
    encrypted_filename  text not null,
    filename_nonce      text not null,
    mime_type           text,
    size_bytes          bigint not null,
    storage_path        text not null,
    created_at          timestamptz not null default now()
);

alter table public.attachments enable row level security;

create policy "attachments_select_visible"
    on public.attachments for select
    to authenticated
    using (exists (select 1 from public.my_item_grant_roles(attachments.item_id)));

create policy "attachments_insert_editors"
    on public.attachments for insert
    to authenticated
    with check (
        exists (
            select 1 from public.my_item_grant_roles(attachments.item_id) r
            where r in ('owner', 'edit_share', 'edit')
        )
    );

create policy "attachments_delete_editors"
    on public.attachments for delete
    to authenticated
    using (
        exists (
            select 1 from public.my_item_grant_roles(attachments.item_id) r
            where r in ('owner', 'edit_share', 'edit')
        )
    );

create index idx_attachments_item on public.attachments(item_id);

-- Append-only security audit log. Detail is always non-secret metadata
-- (never key material or plaintext credential values) — same invariant the
-- original desktop app enforced. No update/delete grants exist for the
-- `authenticated` role at all, so the log cannot be edited or purged from
-- the client under any RLS policy.
create table public.audit_log (
    id            uuid primary key default gen_random_uuid(),
    user_id       text not null references public.user_directory(id),
    event_type    text not null check (event_type in (
                        'unlock', 'lock', 'failed_unlock',
                        'item_created', 'item_viewed', 'item_edited', 'item_deleted',
                        'item_shared', 'item_unshared', 'role_changed',
                        'item_key_rotated', 'group_key_rotated',
                        'export', 'import', 'password_changed', 'vault_reset'
                    )),
    item_id       uuid,
    detail        text,
    occurred_at   timestamptz not null default now()
);

alter table public.audit_log enable row level security;

create policy "audit_log_select_own"
    on public.audit_log for select
    to authenticated
    using (user_id = public.current_user_id());

create policy "audit_log_insert_own"
    on public.audit_log for insert
    to authenticated
    with check (user_id = public.current_user_id());

create index idx_audit_log_user_time on public.audit_log(user_id, occurred_at desc);
