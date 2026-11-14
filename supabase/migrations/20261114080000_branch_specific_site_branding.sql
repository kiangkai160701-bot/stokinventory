-- Per-branch website branding and branch-name editing for stokinventory.
-- Preserve the existing global branding by copying it to every current branch.
create table if not exists private.inventory_branch_site_settings (
  branch_id uuid primary key references private.inventory_branches(id) on delete cascade,
  site_name text not null default 'ไข่หวานบ้านซูชิ',
  logo_data text,
  updated_at timestamptz not null default now(),
  constraint inventory_branch_site_settings_name_length
    check (char_length(site_name) between 1 and 60),
  constraint inventory_branch_site_settings_logo_size
    check (logo_data is null or char_length(logo_data) <= 2500000)
);

alter table private.inventory_branch_site_settings enable row level security;
revoke all on private.inventory_branch_site_settings from public, anon, authenticated;

insert into private.inventory_branch_site_settings(branch_id, site_name, logo_data, updated_at)
select b.id, coalesce(s.site_name, 'ไข่หวานบ้านซูชิ'), s.logo_data, now()
from private.inventory_branches b
left join private.inventory_site_settings s on s.id = true
on conflict (branch_id) do nothing;

create or replace function public.api_site_brand_get(p_branch_id uuid)
returns jsonb language sql security definer set search_path = ''
as $$
  select jsonb_build_object(
    'ok', true,
    'siteName', coalesce(s.site_name, 'ไข่หวานบ้านซูชิ'),
    'logoData', s.logo_data,
    'branchName', b.name
  )
  from private.inventory_branches b
  left join private.inventory_branch_site_settings s on s.branch_id = b.id
  where b.id = p_branch_id and b.active
  union all
  select jsonb_build_object('ok', false, 'error', 'ไม่พบสาขาที่เลือก')
  where not exists (select 1 from private.inventory_branches b where b.id = p_branch_id and b.active)
  limit 1;
$$;

create or replace function public.api_site_brand_update(
  p_token text, p_branch_id uuid, p_site_name text, p_branch_name text, p_logo_data text
)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_name text;
  v_session_branch uuid;
  v_admin jsonb;
  v_site_name text := nullif(trim(coalesce(p_site_name, '')), '');
  v_branch_name text := nullif(trim(coalesce(p_branch_name, '')), '');
begin
  select username, branch_id into v_name, v_session_branch
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now()
  for update;

  if v_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select account into v_admin from private.inventory_global_admin
  where id = true and lower(account->>'name') = lower(v_name)
    and coalesce((account->>'owner')::boolean, false) is true;

  if v_admin is null or lower(v_name) <> 'kiangkai' then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลหลัก kiangkai เท่านั้นที่เปลี่ยนข้อมูลเว็บไซต์ได้');
  end if;

  if v_session_branch is distinct from p_branch_id then
    return jsonb_build_object('ok', false, 'error', 'กรุณาเข้าสู่สาขาที่ต้องการแก้ไขก่อน');
  end if;

  if not exists (select 1 from private.inventory_branches where id = p_branch_id and active) then
    return jsonb_build_object('ok', false, 'error', 'ไม่พบสาขาที่เลือกหรือสาขาถูกปิดใช้งาน');
  end if;

  if v_site_name is null or char_length(v_site_name) > 60 then
    return jsonb_build_object('ok', false, 'error', 'ชื่อเว็บไซต์ต้องมี 1–60 ตัวอักษร');
  end if;

  if v_branch_name is null or char_length(v_branch_name) < 2 or char_length(v_branch_name) > 80 then
    return jsonb_build_object('ok', false, 'error', 'ชื่อสาขาต้องมี 2–80 ตัวอักษร');
  end if;

  if exists (select 1 from private.inventory_branches
             where lower(name) = lower(v_branch_name) and id <> p_branch_id) then
    return jsonb_build_object('ok', false, 'error', 'มีชื่อสาขานี้แล้ว');
  end if;

  if p_logo_data is not null and (
    char_length(p_logo_data) > 2500000
    or p_logo_data !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$'
  ) then
    return jsonb_build_object('ok', false, 'error', 'ไฟล์โลโก้ไม่ถูกต้องหรือมีขนาดใหญ่เกินไป');
  end if;

  update private.inventory_branches set name = v_branch_name where id = p_branch_id;

  insert into private.inventory_branch_site_settings(branch_id, site_name, logo_data, updated_at)
  values (p_branch_id, v_site_name, p_logo_data, now())
  on conflict (branch_id) do update
    set site_name = excluded.site_name, logo_data = excluded.logo_data, updated_at = now();

  return jsonb_build_object('ok', true, 'siteName', v_site_name,
                            'logoData', p_logo_data, 'branchName', v_branch_name);
end;
$$;

revoke all on function public.api_site_brand_get(uuid) from public;
grant execute on function public.api_site_brand_get(uuid) to anon, authenticated;
revoke all on function public.api_site_brand_update(text, uuid, text, text, text) from public, anon;
grant execute on function public.api_site_brand_update(text, uuid, text, text, text) to anon, authenticated;
