-- Allow larger, high-resolution site logos.
-- The browser converts uploaded images to WebP (max 1800px / 1.8 MB)
-- before sending them to the shared branding RPC.

alter table private.inventory_site_settings
  drop constraint if exists inventory_site_settings_logo_size;
alter table private.inventory_site_settings
  add constraint inventory_site_settings_logo_size
  check (logo_data is null or char_length(logo_data) <= 2500000);

create or replace function public.api_site_brand_update(p_token text, p_site_name text, p_logo_data text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
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

  select account into v_admin
  from private.inventory_global_admin
  where id = true and lower(account->>'name') = lower(v_name)
    and coalesce((account->>'owner')::boolean, false) is true;

  if v_admin is null or lower(v_name) <> 'kiangkai' then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลหลัก kiangkai เท่านั้นที่เปลี่ยนข้อมูลเว็บไซต์ได้');
  end if;

  if v_site_name is null or char_length(v_site_name) > 60 then
    return jsonb_build_object('ok', false, 'error', 'ชื่อเว็บไซต์ต้องมี 1–60 ตัวอักษร');
  end if;

  if p_logo_data is not null and (
    char_length(p_logo_data) > 2500000
    or p_logo_data !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$'
  ) then
    return jsonb_build_object('ok', false, 'error', 'ไฟล์โลโก้ไม่ถูกต้องหรือมีขนาดใหญ่เกินไป');
  end if;

  insert into private.inventory_site_settings(id, site_name, logo_data, updated_at)
  values (true, v_site_name, p_logo_data, now())
  on conflict (id) do update
    set site_name = excluded.site_name,
        logo_data = excluded.logo_data,
        updated_at = now();

  return jsonb_build_object('ok', true, 'siteName', v_site_name, 'logoData', p_logo_data);
end;
$function$;
