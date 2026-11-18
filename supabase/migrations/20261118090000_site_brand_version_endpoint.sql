-- Lightweight branding version endpoint.
-- Returns metadata only; the potentially large base64 logo is served only
-- by api_site_brand_get when the version changes or the browser has no cache.
create or replace function public.api_site_brand_version_get(p_branch_id uuid)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'ok', true,
    'updatedAt', s.updated_at,
    'branchName', b.name
  )
  from private.inventory_branches b
  left join private.inventory_branch_site_settings s on s.branch_id = b.id
  where b.id = p_branch_id and b.active

  union all

  select jsonb_build_object('ok', false, 'error', 'ไม่พบสาขาที่เลือก')
  where not exists (
    select 1
    from private.inventory_branches b
    where b.id = p_branch_id and b.active
  )
  limit 1;
$$;

revoke all on function public.api_site_brand_version_get(uuid) from public;
grant execute on function public.api_site_brand_version_get(uuid) to anon, authenticated;
