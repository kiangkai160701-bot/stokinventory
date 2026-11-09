-- Global website branding shared by every inventory branch.
-- Logo is stored as a bounded raster data URL because inventory accounts use
-- application-managed sessions rather than Supabase Auth JWTs for Storage uploads.

create table if not exists private.inventory_site_settings (
  id boolean primary key default true check (id),
  site_name text not null default 'ไข่หวานบ้านซูชิ',
  logo_data text,
  updated_at timestamptz not null default now(),
  constraint inventory_site_settings_name_length check (char_length(site_name) between 1 and 60),
  constraint inventory_site_settings_logo_size check (logo_data is null or char_length(logo_data) <= 700000)
);
alter table private.inventory_site_settings enable row level security;
revoke all on private.inventory_site_settings from public, anon, authenticated;
insert into private.inventory_site_settings(id, site_name, logo_data)
values (true, 'ไข่หวานบ้านซูชิ', null)
on conflict (id) do nothing;

create or replace function public.api_site_brand_get()
returns jsonb language sql security definer set search_path = ''
as $$
  select jsonb_build_object('ok', true, 'siteName', site_name, 'logoData', logo_data)
  from private.inventory_site_settings where id = true
  union all
  select jsonb_build_object('ok', true, 'siteName', 'ไข่หวานบ้านซูชิ', 'logoData', null)
  where not exists (select 1 from private.inventory_site_settings where id = true)
  limit 1;
$$;

create or replace function public.api_site_brand_update(p_token text, p_site_name text, p_logo_data text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_name text;
  v_admin jsonb;
  v_site_name text := nullif(trim(coalesce(p_site_name, '')), '');
begin
  select username into v_name
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();
  if v_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;
  select account into v_admin from private.inventory_global_admin
  where id = true and lower(account->>'name') = lower(v_name)
    and coalesce((account->>'owner')::boolean, false) is true;
  if v_admin is null or lower(v_name) <> 'kiangkai' then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลหลัก kiangkai เท่านั้นที่เปลี่ยนข้อมูลเว็บไซต์ได้');
  end if;
  if v_site_name is null or char_length(v_site_name) > 60 then
    return jsonb_build_object('ok', false, 'error', 'ชื่อเว็บไซต์ต้องมี 1–60 ตัวอักษร');
  end if;
  if p_logo_data is not null and (
    char_length(p_logo_data) > 700000
    or p_logo_data !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$'
  ) then
    return jsonb_build_object('ok', false, 'error', 'ไฟล์โลโก้ไม่ถูกต้องหรือมีขนาดใหญ่เกินไป');
  end if;
  insert into private.inventory_site_settings(id, site_name, logo_data, updated_at)
  values (true, v_site_name, p_logo_data, now())
  on conflict (id) do update
    set site_name = excluded.site_name, logo_data = excluded.logo_data, updated_at = now();
  return jsonb_build_object('ok', true, 'siteName', v_site_name, 'logoData', p_logo_data);
end;
$$;

revoke all on function public.api_site_brand_get() from public;
grant execute on function public.api_site_brand_get() to anon, authenticated;
revoke all on function public.api_site_brand_update(text, text, text) from public, anon;
grant execute on function public.api_site_brand_update(text, text, text) to anon, authenticated;
