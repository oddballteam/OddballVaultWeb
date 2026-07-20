-- Attachment bytes are encrypted client-side before upload and decrypted
-- client-side after download (Supabase never sees plaintext). Storage
-- objects are keyed "<item_id>/<attachment_id>" so RLS can reuse the same
-- item-sharing check as the `attachments` table, instead of a separate
-- per-user folder scheme that wouldn't understand shared items.
insert into storage.buckets (id, name, public)
values ('attachments', 'attachments', false)
on conflict (id) do nothing;

create policy "attachment_objects_select_visible"
    on storage.objects for select
    to authenticated
    using (
        bucket_id = 'attachments'
        and exists (
            select 1 from public.my_item_grant_roles((storage.foldername(name))[1]::uuid)
        )
    );

create policy "attachment_objects_insert_editors"
    on storage.objects for insert
    to authenticated
    with check (
        bucket_id = 'attachments'
        and exists (
            select 1 from public.my_item_grant_roles((storage.foldername(name))[1]::uuid) r
            where r in ('owner', 'edit_share', 'edit')
        )
    );

create policy "attachment_objects_delete_editors"
    on storage.objects for delete
    to authenticated
    using (
        bucket_id = 'attachments'
        and exists (
            select 1 from public.my_item_grant_roles((storage.foldername(name))[1]::uuid) r
            where r in ('owner', 'edit_share', 'edit')
        )
    );
