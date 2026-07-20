-- Public directory: lets any authenticated user look up a recipient's public
-- key by email in order to share an item with them. Contains no secrets.
create table public.user_directory (
    id          text primary key,           -- Okta 'sub'
    email       text not null unique,
    public_key  text not null,              -- base64 SPKI, RSA-OAEP-3072
    created_at  timestamptz not null default now()
);

alter table public.user_directory enable row level security;

create policy "user_directory_select_any_authenticated"
    on public.user_directory for select
    to authenticated
    using (true);

create policy "user_directory_insert_self"
    on public.user_directory for insert
    to authenticated
    with check (id = public.current_user_id());

create policy "user_directory_update_self"
    on public.user_directory for update
    to authenticated
    using (id = public.current_user_id())
    with check (id = public.current_user_id());

-- Private crypto material: the master-password-derived key never leaves the
-- browser, so everything here is either already encrypted under it or,
-- like the KDF salt, not secret on its own. No other user may ever select
-- from this table.
create table public.app_users (
    id                      text primary key references public.user_directory(id) on delete cascade,
    encrypted_private_key   text not null,   -- AES-256-GCM(Master Key, PKCS8 RSA-OAEP-3072 private key)
    private_key_nonce       text not null,
    kdf_salt                text not null,
    kdf_time_cost           int not null,
    kdf_memory_cost         int not null,
    kdf_parallelism         int not null,
    key_check_ciphertext    text not null,   -- AES-256-GCM(Master Key, "KEY_CHECK_OK") — verifies unlock
    key_check_nonce         text not null,
    created_at              timestamptz not null default now()
);

alter table public.app_users enable row level security;

create policy "app_users_select_self"
    on public.app_users for select
    to authenticated
    using (id = public.current_user_id());

create policy "app_users_insert_self"
    on public.app_users for insert
    to authenticated
    with check (id = public.current_user_id());

create policy "app_users_update_self"
    on public.app_users for update
    to authenticated
    using (id = public.current_user_id())
    with check (id = public.current_user_id());
