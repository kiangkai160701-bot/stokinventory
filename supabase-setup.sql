-- ฐานข้อมูลกลางสำหรับระบบสต็อกไข่หวานบ้านซูชิ
-- เปิด SQL Editor ใน Supabase แล้ววางไฟล์นี้ทั้งหมด จากนั้นกด Run หนึ่งครั้ง

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;

create table if not exists private.inventory_state (
  id boolean primary key default true check (id),
  data jsonb not null,
  version bigint not null default 1,
  updated_at timestamptz not null default now()
);

create table if not exists private.inventory_sessions (
  token_hash text primary key,
  username text not null,
  expires_at timestamptz not null
);
alter table private.inventory_sessions add column if not exists last_seen timestamptz;
alter table private.inventory_sessions alter column last_seen set default now();

create table if not exists private.inventory_login_failures (
  username text primary key,
  failures integer not null default 0,
  blocked_until timestamptz
);

alter table private.inventory_state enable row level security;
alter table private.inventory_sessions enable row level security;
alter table private.inventory_login_failures enable row level security;
revoke all on schema private from public, anon, authenticated;
revoke all on all tables in schema private from public, anon, authenticated;

insert into private.inventory_state (id, data, version)
values (
  true,
  jsonb_build_object(
    'users', jsonb_build_array(jsonb_build_object(
      'name', 'เจ้าของร้าน',
      'pin', encode(extensions.digest('inv:123456', 'sha256'), 'hex'),
      'role', 'admin', 'active', true, 'must', true, 'owner', true,
      'permissions', jsonb_build_object('editStock', true, 'manageLists', true,
        'manageUsers', true, 'deleteUsers', true, 'deleteStock', true, 'managePermissions', true, 'resetData', true)
    )),
    'products', '[]'::jsonb,
    'log', '[]'::jsonb,
    'roles', jsonb_build_object('admin', 'ผู้ดูแลระบบ', 'supervisor', 'หัวหน้างาน', 'staff', 'พนักงานคลัง', 'viewer', 'ผู้ดูข้อมูล'),
    'categories', jsonb_build_array('ปลาและอาหารทะเล', 'ข้าวและเส้น', 'สาหร่ายและเครื่องปรุง', 'ผักและผลไม้', 'บรรจุภัณฑ์', 'อื่นๆ'),
    'units', jsonb_build_array('กิโลกรัม', 'กรัม', 'ลิตร', 'มิลลิลิตร', 'ชิ้น', 'แพ็ค', 'กล่อง', 'ขวด', 'ถุง')
  ),
  1
)
on conflict do nothing;

create or replace function public.api_safe_state(p_data jsonb)
returns jsonb
language sql immutable
set search_path = ''
as $$
  select jsonb_set(
    p_data - 'theme',
    '{users}',
    coalesce((select jsonb_agg(x.user_data - 'pin' order by x.position) from jsonb_array_elements(coalesce(p_data->'users', '[]'::jsonb)) with ordinality as x(user_data, position)), '[]'::jsonb)
  );
$$;

create or replace function public.api_bootstrap_status()
returns jsonb
language sql security definer
set search_path = ''
as $$
  select jsonb_build_object('ready', true, 'firstLogin', coalesce((data->'users'->0->>'must')::boolean, false))
  from private.inventory_state where id = true;
$$;

create or replace function public.api_login(p_name text, p_pin_hash text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_name text := lower(trim(coalesce(p_name, '')));
  v_data jsonb;
  v_user jsonb;
  v_fail private.inventory_login_failures%rowtype;
  v_token text;
  v_version bigint;
begin
  if v_name = '' or coalesce(p_pin_hash, '') !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok', false, 'error', 'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง');
  end if;
  insert into private.inventory_login_failures(username) values (v_name) on conflict do nothing;
  select * into v_fail from private.inventory_login_failures where username = v_name for update;
  if v_fail.blocked_until is not null and v_fail.blocked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'ลองเข้าสู่ระบบหลายครั้ง กรุณารอสักครู่');
  end if;
  select data, version into v_data, v_version from private.inventory_state where id = true;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name') = v_name;
  if v_user is null or coalesce(v_user->>'pin','') <> p_pin_hash or coalesce((v_user->>'active')::boolean, false) is not true then
    update private.inventory_login_failures
      set failures = case when failures >= 4 then 0 else failures + 1 end,
          blocked_until = case when failures >= 4 then now() + interval '60 seconds' else null end
      where username = v_name;
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้หรือรหัสไม่ถูกต้อง');
  end if;
  delete from private.inventory_login_failures where username = v_name;
  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  insert into private.inventory_sessions(token_hash, username, expires_at)
    values (encode(extensions.digest(v_token, 'sha256'), 'hex'), v_name, now() + interval '7 days');
  return jsonb_build_object('ok', true, 'token', v_token, 'state', public.api_safe_state(v_data), 'me', v_user - 'pin', 'version', v_version);
end;
$$;

create or replace function public.api_get_state(p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare v_name text; v_data jsonb; v_user jsonb; v_version bigint;
begin
  select username into v_name from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id = true;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name') = v_name;
  if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data), 'me', v_user - 'pin', 'version', v_version);
end;
$$;

create or replace function public.api_set_theme(p_token text, p_theme text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare v_name text; v_version bigint;
begin
  select username into v_name from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  if coalesce(p_theme, '') not in ('sakura','matcha','ocean','lavender','peach','lemon','mint','grape','coral','ramune','taro','nori','midnight') then
    return jsonb_build_object('ok', false, 'error', 'ไม่พบธีมที่เลือก');
  end if;
  update private.inventory_state
    set data = jsonb_set(data, '{theme}', to_jsonb(p_theme), true), version = version + 1, updated_at = now()
    where id = true returning version into v_version;
  return jsonb_build_object('ok', true, 'version', v_version);
end;
$$;

create or replace function public.api_sync(p_token text, p_base jsonb, p_data jsonb)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_name text; v_data jsonb; v_user jsonb; v_version bigint; v_next jsonb; v_users jsonb;
  v_perm jsonb; v_log jsonb; v_add jsonb; v_products_changed boolean;
  v_users_changed boolean; v_lists_changed boolean;
begin
  select username into v_name from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id = true for update;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name') = v_name;
  if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  v_perm := coalesce(v_user->'permissions', '{}'::jsonb);
  v_products_changed := coalesce(p_base->'products', '[]'::jsonb) is distinct from coalesce(p_data->'products', '[]'::jsonb);
  v_users_changed := coalesce(p_base->'users', '[]'::jsonb) is distinct from coalesce(p_data->'users', '[]'::jsonb);
  v_lists_changed := coalesce(p_base->'roles', '{}'::jsonb) is distinct from coalesce(p_data->'roles', '{}'::jsonb)
    or coalesce(p_base->'categories', '[]'::jsonb) is distinct from coalesce(p_data->'categories', '[]'::jsonb)
    or coalesce(p_base->'units', '[]'::jsonb) is distinct from coalesce(p_data->'units', '[]'::jsonb);

  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_products_changed and not coalesce((v_perm->>'editStock')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการสต็อก');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'manageUsers')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการผู้ใช้');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'deleteUsers')::boolean, false) and exists (
    select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) oldu
    where not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name')
  ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบผู้ใช้'); end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'managePermissions')::boolean, false) then
    if exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      join jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu on oldu->>'name'=newu->>'name'
      where coalesce(oldu->>'role','') is distinct from coalesce(newu->>'role','')
         or coalesce(oldu->'permissions','{}'::jsonb) is distinct from coalesce(newu->'permissions','{}'::jsonb)
    ) or exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu where oldu->>'name'=newu->>'name')
        and (
          newu->>'role' in ('admin','supervisor')
          or coalesce(newu->'permissions','{}'::jsonb) is distinct from
            case newu->>'role'
              when 'admin' then '{"editStock":true,"manageLists":true,"manageUsers":true,"deleteUsers":true,"deleteStock":true,"managePermissions":true}'::jsonb
              when 'supervisor' then '{"editStock":true,"manageLists":true,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
              when 'staff' then '{"editStock":true,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
              else '{"editStock":false,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
            end
        )
    ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์กำหนดตำแหน่งหรือสิทธิ์'); end if;
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_lists_changed and not coalesce((v_perm->>'manageLists')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์แก้ไขรายการ');
  end if;

  -- ป้องกันการเขียนทับการแก้ไขของอีกเครื่องในหมวดเดียวกัน
  if v_products_changed and v_data->'products' is distinct from p_base->'products' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขสต็อกจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่แล้วทำรายการอีกครั้ง');
  end if;
  if v_users_changed and public.api_safe_state(v_data)->'users' is distinct from p_base->'users' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขผู้ใช้จากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;
  if v_lists_changed and (v_data->'roles' is distinct from p_base->'roles' or v_data->'categories' is distinct from p_base->'categories' or v_data->'units' is distinct from p_base->'units') then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขรายการจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;

  v_next := v_data;
  if v_products_changed then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'deleteStock')::boolean, false) then
      if exists(select 1 from jsonb_array_elements(v_data->'products') oldp where not exists (
        select 1 from jsonb_array_elements(coalesce(p_data->'products','[]'::jsonb)) newp where newp->>'id' = oldp->>'id'
      )) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบวัตถุดิบ'); end if;
    end if;
    v_next := jsonb_set(v_next, '{products}', coalesce(p_data->'products', '[]'::jsonb));
  end if;
  if v_users_changed then
    if exists(select 1 from jsonb_array_elements(v_data->'users') oldu where coalesce((oldu->>'owner')::boolean,false)
      and not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name' and newu->>'role'=oldu->>'role' and coalesce((newu->>'active')::boolean,false))) then
      return jsonb_build_object('ok', false, 'error', 'ไม่สามารถปิดหรือลบบัญชีผู้ดูแลหลักได้');
    end if;
    if not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u where u->>'role'='admin' and coalesce((u->>'active')::boolean,false)) then
      return jsonb_build_object('ok', false, 'error', 'ต้องมีผู้ดูแลที่เปิดใช้งานอย่างน้อยหนึ่งบัญชี');
    end if;
    select coalesce(jsonb_agg(
      case when newu.user_data ? 'pin' then newu.user_data else newu.user_data || jsonb_build_object('pin', oldu.user_data->'pin') end order by newu.position
    ), '[]'::jsonb) into v_users
    from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) with ordinality as newu(user_data, position)
    left join jsonb_array_elements(v_data->'users') as oldu(user_data) on oldu.user_data->>'name'=newu.user_data->>'name';
    if exists(select 1 from jsonb_array_elements(v_users) as u(user_data) where coalesce(u.user_data->>'pin','') !~ '^[0-9a-f]{64}$') then
      return jsonb_build_object('ok', false, 'error', 'บัญชีผู้ใช้ต้องมีรหัส 6 หลักก่อนบันทึก');
    end if;
    v_next := jsonb_set(v_next, '{users}', v_users);
  end if;
  if v_lists_changed then
    v_next := jsonb_set(v_next, '{roles}', coalesce(p_data->'roles','{}'::jsonb));
    v_next := jsonb_set(v_next, '{categories}', coalesce(p_data->'categories','[]'::jsonb));
    v_next := jsonb_set(v_next, '{units}', coalesce(p_data->'units','[]'::jsonb));
  end if;

  -- ประวัติเป็นข้อมูลเพิ่มต่อท้าย ไม่ลบประวัติที่อุปกรณ์อื่นบันทึกไว้
  select coalesce(jsonb_agg(entry), '[]'::jsonb) into v_add
    from jsonb_array_elements(coalesce(p_data->'log','[]'::jsonb)) entry
    where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'log','[]'::jsonb)) oldentry where oldentry = entry);
  if jsonb_array_length(v_add) > 0 then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'editStock')::boolean, false) then
      return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์บันทึกประวัติสต็อก');
    end if;
    select coalesce(jsonb_agg((entry - 'user' - 'role') || jsonb_build_object('user', v_name, 'role', coalesce(v_data->'roles'->>(v_user->>'role'), v_user->>'role', 'พนักงานคลัง')) order by (entry->>'ts')::numeric desc), '[]'::jsonb)
      into v_log from jsonb_array_elements(v_add) entry;
    select coalesce(jsonb_agg(item order by ord), '[]'::jsonb) into v_log
      from (select item, ord from jsonb_array_elements(v_log || coalesce(v_data->'log','[]'::jsonb)) with ordinality as x(item,ord) order by ord limit 500) recent;
    v_next := jsonb_set(v_next, '{log}', v_log);
  end if;

  update private.inventory_state set data = v_next, version = version + 1, updated_at = now() where id = true returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_next), 'version', v_version);
end;
$$;

create or replace function public.api_reset_data(p_token text, p_scope text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_name text;
  v_data jsonb;
  v_user jsonb;
  v_version bigint;
begin
  select username into v_name
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();
  if v_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select data into v_data from private.inventory_state where id = true for update;
  select value into v_user
  from jsonb_array_elements(v_data->'users')
  where lower(value->>'name') = lower(v_name);
  if v_user is null or (
    coalesce((v_user->>'owner')::boolean, false) is not true
    and lower(v_user->>'name') <> 'kiangkai'
    and coalesce(v_user->>'role', '') <> 'admin'
    and coalesce((v_user->'permissions'->>'resetData')::boolean, false) is not true
  ) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์รีเซ็ตข้อมูล');
  end if;
  if p_scope is null or p_scope not in ('products', 'history', 'users', 'all') then
    return jsonb_build_object('ok', false, 'error', 'ขอบเขตการรีเซ็ตไม่ถูกต้อง');
  end if;

  if p_scope in ('products', 'all') then
    v_data := jsonb_set(v_data, '{products}', '[]'::jsonb);
  end if;
  if p_scope in ('history', 'all', 'users') then
    v_data := jsonb_set(v_data, '{log}', '[]'::jsonb);
  end if;
  if p_scope = 'users' then
    select coalesce(jsonb_agg(value), '[]'::jsonb) into v_user
    from jsonb_array_elements(v_data->'users') value
    where coalesce((value->>'owner')::boolean, false) or lower(value->>'name') = 'kiangkai';
    v_data := jsonb_set(v_data, '{users}', v_user);
  end if;

  v_data := jsonb_set(v_data, '{lastReset}', jsonb_build_object(
    'scope', p_scope,
    'user', v_name,
    'ts', floor(extract(epoch from clock_timestamp()) * 1000)::bigint
  ), true);

  update private.inventory_state
  set data = v_data, version = version + 1, updated_at = now()
  where id = true
  returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data), 'version', v_version);
end;
$$;

create or replace function public.api_change_pin(p_token text, p_old_hash text, p_new_hash text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare v_name text; v_data jsonb; v_user jsonb; v_users jsonb; v_version bigint;
begin
  if coalesce(p_new_hash,'') !~ '^[0-9a-f]{64}$' then return jsonb_build_object('ok', false, 'error', 'รหัสใหม่ไม่ถูกต้อง'); end if;
  select username into v_name from private.inventory_sessions where token_hash = encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data into v_data from private.inventory_state where id = true for update;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name') = v_name;
  if v_user is null or (coalesce((v_user->>'must')::boolean,false) is false and v_user->>'pin' <> p_old_hash) then
    return jsonb_build_object('ok', false, 'error', 'รหัสปัจจุบันไม่ถูกต้อง');
  end if;
  select coalesce(jsonb_agg(case when lower(value->>'name')=v_name then value || jsonb_build_object('pin',p_new_hash,'must',false) else value end),'[]'::jsonb)
    into v_users from jsonb_array_elements(v_data->'users') value;
  v_data := jsonb_set(v_data,'{users}',v_users);
  update private.inventory_state set data=v_data, version=version+1, updated_at=now() where id=true returning version into v_version;
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',(select value - 'pin' from jsonb_array_elements(v_users) value where lower(value->>'name')=v_name),'version',v_version);
end;
$$;

create or replace function public.api_update_owner_account(p_token text, p_old_hash text, p_new_name text, p_new_hash text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_token_hash text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_old_name text;
  v_new_name text := lower(trim(coalesce(p_new_name, '')));
  v_data jsonb;
  v_user jsonb;
  v_users jsonb;
  v_version bigint;
begin
  if v_new_name = '' or length(v_new_name) < 3 or length(v_new_name) > 20
     or coalesce(p_old_hash, '') !~ '^[0-9a-f]{64}$'
     or coalesce(p_new_hash, '') !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok', false, 'error', 'ข้อมูลบัญชีไม่ถูกต้อง');
  end if;
  select username into v_old_name from private.inventory_sessions
    where token_hash = v_token_hash and expires_at > now();
  if v_old_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;
  select data into v_data from private.inventory_state where id = true for update;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name') = v_old_name;
  if v_user is null or coalesce((v_user->>'owner')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลหลักเท่านั้นที่เปลี่ยนบัญชีนี้ได้');
  end if;
  if coalesce(v_user->>'pin', '') <> p_old_hash then
    return jsonb_build_object('ok', false, 'error', 'รหัสปัจจุบันไม่ถูกต้อง');
  end if;
  if exists (select 1 from jsonb_array_elements(v_data->'users') x
             where lower(x->>'name') = v_new_name and lower(x->>'name') <> v_old_name) then
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้นี้มีคนใช้แล้ว');
  end if;
  select coalesce(jsonb_agg(case when lower(value->>'name') = v_old_name
    then value || jsonb_build_object('name', v_new_name, 'pin', p_new_hash, 'must', false)
    else value end), '[]'::jsonb)
    into v_users from jsonb_array_elements(v_data->'users') value;
  v_data := jsonb_set(v_data, '{users}', v_users);
  update private.inventory_state set data = v_data, version = version + 1, updated_at = now()
    where id = true returning version into v_version;
  update private.inventory_sessions set username = v_new_name where username = v_old_name;
  delete from private.inventory_login_failures where username in (v_old_name, v_new_name);
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data),
    'me', (select value - 'pin' from jsonb_array_elements(v_users) value where lower(value->>'name') = v_new_name),
    'version', v_version);
end;
$$;

create or replace function public.api_update_username(p_token text, p_old_hash text, p_new_name text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_token_hash text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_old_name text;
  v_new_name text := lower(trim(coalesce(p_new_name, '')));
  v_data jsonb;
  v_user jsonb;
  v_users jsonb;
  v_version bigint;
begin
  if v_new_name = '' or length(v_new_name) < 3 or length(v_new_name) > 20
     or coalesce(p_old_hash, '') !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok', false, 'error', 'ข้อมูลบัญชีไม่ถูกต้อง');
  end if;
  select username into v_old_name from private.inventory_sessions
    where token_hash = v_token_hash and expires_at > now();
  if v_old_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;
  select data into v_data from private.inventory_state where id = true for update;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name') = v_old_name;
  if v_user is null or (coalesce((v_user->>'owner')::boolean, false) is not true and coalesce(v_user->>'role', '') <> 'admin') then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลระบบและผู้ดูแลหลักเท่านั้นที่แก้ไขชื่อได้');
  end if;
  if coalesce(v_user->>'pin', '') <> p_old_hash then
    return jsonb_build_object('ok', false, 'error', 'รหัสปัจจุบันไม่ถูกต้อง');
  end if;
  if exists (select 1 from jsonb_array_elements(v_data->'users') x
             where lower(x->>'name') = v_new_name and lower(x->>'name') <> v_old_name) then
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้นี้มีคนใช้แล้ว');
  end if;
  select coalesce(jsonb_agg(case when lower(value->>'name') = v_old_name
    then value || jsonb_build_object('name', v_new_name)
    else value end), '[]'::jsonb)
    into v_users from jsonb_array_elements(v_data->'users') value;
  v_data := jsonb_set(v_data, '{users}', v_users);
  update private.inventory_state set data = v_data, version = version + 1, updated_at = now()
    where id = true returning version into v_version;
  update private.inventory_sessions set username = v_new_name where username = v_old_name;
  delete from private.inventory_login_failures where username in (v_old_name, v_new_name);
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data),
    'me', (select value - 'pin' from jsonb_array_elements(v_users) value where lower(value->>'name') = v_new_name),
    'version', v_version);
end;
$$;

create or replace function public.api_logout(p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
begin
  delete from private.inventory_sessions where token_hash = encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex');
  return jsonb_build_object('ok',true);
end;
$$;

create or replace function public.api_presence_tick(p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_username text;
  v_users jsonb;
begin
  update private.inventory_sessions
    set last_seen = now()
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
      and expires_at > now()
    returning username into v_username;
  if v_username is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;
  select coalesce(jsonb_agg(active.username order by active.username), '[]'::jsonb)
    into v_users
    from (
      select distinct username
      from private.inventory_sessions
      where expires_at > now() and last_seen > now() - interval '50 seconds'
    ) active;
  return jsonb_build_object('ok', true, 'users', v_users);
end;
$$;

revoke all on function public.api_safe_state(jsonb) from public, anon, authenticated;
revoke all on function public.api_bootstrap_status() from public;
revoke all on function public.api_login(text,text) from public;
revoke all on function public.api_get_state(text) from public;
revoke all on function public.api_set_theme(text,text) from public;
revoke all on function public.api_sync(text,jsonb,jsonb) from public;
revoke all on function public.api_reset_data(text,text) from public;
revoke all on function public.api_change_pin(text,text,text) from public;
revoke all on function public.api_update_owner_account(text,text,text,text) from public;
revoke all on function public.api_update_username(text,text,text) from public;
revoke all on function public.api_logout(text) from public;
revoke all on function public.api_presence_tick(text) from public;
grant execute on function public.api_bootstrap_status() to anon, authenticated;
grant execute on function public.api_login(text,text) to anon, authenticated;
grant execute on function public.api_get_state(text) to anon, authenticated;
grant execute on function public.api_set_theme(text,text) to anon, authenticated;
grant execute on function public.api_sync(text,jsonb,jsonb) to anon, authenticated;
grant execute on function public.api_reset_data(text,text) to anon, authenticated;
grant execute on function public.api_change_pin(text,text,text) to anon, authenticated;
grant execute on function public.api_update_owner_account(text,text,text,text) to anon, authenticated;
grant execute on function public.api_update_username(text,text,text) to anon, authenticated;
grant execute on function public.api_logout(text) to anon, authenticated;
grant execute on function public.api_presence_tick(text) to anon, authenticated;

-- Securely report actual database usage to active owner/admin sessions.
-- Default quota is Supabase Free (500 MiB); update for another plan.
create or replace function public.api_storage_usage(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_username text;
  v_user jsonb;
  v_used_bytes bigint;
  v_quota_bytes bigint := 500::bigint * 1024 * 1024;
begin
  select username into v_username
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();

  if v_username is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select u.value into v_user
  from private.inventory_state state
  cross join lateral jsonb_array_elements(coalesce(state.data->'users', '[]'::jsonb)) as u(value)
  where state.id = true and lower(u.value->>'name') = lower(v_username);

  if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่สามารถดูข้อมูลพื้นที่ฐานข้อมูลได้');
  end if;

  if coalesce((v_user->>'owner')::boolean, false) is not true
     and coalesce(v_user->>'role', '') <> 'admin' then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลหลักหรือผู้ดูแลระบบเท่านั้นที่ดูข้อมูลนี้ได้');
  end if;

  v_used_bytes := pg_catalog.pg_database_size(pg_catalog.current_database());

  return jsonb_build_object(
    'ok', true,
    'usedBytes', v_used_bytes,
    'quotaBytes', v_quota_bytes,
    'remainingBytes', greatest(v_quota_bytes - v_used_bytes, 0),
    'usedPercent', round(v_used_bytes::numeric * 100 / v_quota_bytes, 2),
    'checkedAt', now(),
    'quotaPlan', 'Free'
  );
end;
$$;

revoke all on function public.api_storage_usage(text) from public, anon, authenticated;
grant execute on function public.api_storage_usage(text) to anon, authenticated;

notify pgrst, 'reload schema';

-- -- Multi-branch support and migration of the current state into พันท้ายนรสิงห์.
-- Multi-branch migration for the sushi inventory app.
-- Keeps the existing state in the Pantai branch and binds every new session to one branch.
begin;

create table if not exists private.inventory_branches (
  id uuid primary key,
  name text not null unique,
  active boolean not null default true,
  created_by text not null default 'kiangkai',
  created_at timestamptz not null default now()
);
insert into private.inventory_branches(id,name,active,created_by)
values ('e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid,'พันท้ายนรสิงห์',true,'kiangkai')
on conflict (id) do nothing;

create table if not exists private.inventory_state_backups (
  backup_key text primary key,
  data jsonb not null,
  version bigint not null,
  saved_at timestamptz not null default now()
);
insert into private.inventory_state_backups(backup_key,data,version)
select 'before-multibranch-20261023',data,version from private.inventory_state where id=true order by updated_at limit 1
on conflict (backup_key) do nothing;

alter table private.inventory_state add column if not exists branch_id uuid;
update private.inventory_state set branch_id='e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid where branch_id is null;
alter table private.inventory_state alter column branch_id set default 'e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid;
alter table private.inventory_state alter column branch_id set not null;
alter table private.inventory_state drop constraint if exists inventory_state_pkey;
alter table private.inventory_state add constraint inventory_state_pkey primary key(branch_id,id);
alter table private.inventory_state drop constraint if exists inventory_state_branch_id_fkey;
alter table private.inventory_state add constraint inventory_state_branch_id_fkey foreign key(branch_id) references private.inventory_branches(id);

alter table private.inventory_sessions add column if not exists branch_id uuid;
update private.inventory_sessions set branch_id='e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid where branch_id is null;
alter table private.inventory_sessions alter column branch_id set default 'e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid;
alter table private.inventory_sessions alter column branch_id set not null;
alter table private.inventory_sessions drop constraint if exists inventory_sessions_branch_id_fkey;
alter table private.inventory_sessions add constraint inventory_sessions_branch_id_fkey foreign key(branch_id) references private.inventory_branches(id);

alter table private.inventory_login_failures add column if not exists branch_id uuid;
update private.inventory_login_failures set branch_id='e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid where branch_id is null;
alter table private.inventory_login_failures alter column branch_id set default 'e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid;
alter table private.inventory_login_failures alter column branch_id set not null;
alter table private.inventory_login_failures drop constraint if exists inventory_login_failures_pkey;
alter table private.inventory_login_failures add constraint inventory_login_failures_pkey primary key(branch_id,username);
alter table private.inventory_login_failures drop constraint if exists inventory_login_failures_branch_id_fkey;
alter table private.inventory_login_failures add constraint inventory_login_failures_branch_id_fkey foreign key(branch_id) references private.inventory_branches(id);

create table if not exists private.inventory_global_admin (
  id boolean primary key default true check(id),
  account jsonb not null,
  updated_at timestamptz not null default now()
);
alter table private.inventory_global_admin enable row level security;
revoke all on private.inventory_global_admin from public,anon,authenticated;
do $$
declare v_account jsonb;
begin
  if not exists(select 1 from private.inventory_global_admin where id=true) then
    select u.value into v_account
    from private.inventory_state s cross join lateral jsonb_array_elements(s.data->'users') u(value)
    where s.id=true and lower(u.value->>'name')='kiangkai' limit 1;
    if v_account is null then
      select u.value into v_account
      from private.inventory_state s cross join lateral jsonb_array_elements(s.data->'users') u(value)
      where s.id=true and coalesce((u.value->>'owner')::boolean,false) limit 1;
    end if;
    if v_account is null then raise exception 'ไม่พบบัญชีผู้ดูแลหลักสำหรับย้ายเป็นบัญชีข้ามสาขา'; end if;
    v_account := v_account || jsonb_build_object('name','kiangkai','role','admin','active',true,'owner',true);
    insert into private.inventory_global_admin(id,account) values(true,v_account);
  end if;
end $$;
update private.inventory_state s
set data=jsonb_set(s.data,'{users}',coalesce((select jsonb_agg(u.value order by u.ord)
  from jsonb_array_elements(s.data->'users') with ordinality u(value,ord)
  where lower(u.value->>'name') <> lower((select account->>'name' from private.inventory_global_admin where id=true))
    and coalesce((u.value->>'owner')::boolean,false) is not true),'[]'::jsonb)),
    version=s.version+1,updated_at=now()
where s.id=true and s.branch_id='e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid
  and exists(select 1 from jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) u(value)
    where lower(u.value->>'name')=lower((select account->>'name' from private.inventory_global_admin where id=true))
       or coalesce((u.value->>'owner')::boolean,false));

create or replace function public.api_branch_list()
returns jsonb language sql security definer set search_path=''
as $$
  select jsonb_build_object('ok',true,'branches',coalesce(jsonb_agg(jsonb_build_object('id',id,'name',name) order by created_at,id),'[]'::jsonb))
  from private.inventory_branches where active;
$$;

create or replace function public.api_branch_login(p_branch_id uuid,p_name text,p_pin_hash text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_name text:=lower(trim(coalesce(p_name,''))); v_data jsonb; v_user jsonb; v_fail private.inventory_login_failures%rowtype; v_token text; v_version bigint; v_branch jsonb;
begin
  if v_name='' or coalesce(p_pin_hash,'') !~ '^[0-9a-f]{64}$' then return jsonb_build_object('ok',false,'error','ข้อมูลเข้าสู่ระบบไม่ถูกต้อง'); end if;
  select jsonb_build_object('id',id,'name',name) into v_branch from private.inventory_branches where id=p_branch_id and active;
  if v_branch is null then return jsonb_build_object('ok',false,'error','ไม่พบสาขาที่เลือก'); end if;
  insert into private.inventory_login_failures(branch_id,username) values(p_branch_id,v_name) on conflict(branch_id,username) do nothing;
  select * into v_fail from private.inventory_login_failures where branch_id=p_branch_id and username=v_name for update;
  if v_fail.blocked_until is not null and v_fail.blocked_until>now() then return jsonb_build_object('ok',false,'error','ลองเข้าสู่ระบบหลายครั้ง กรุณารอสักครู่'); end if;
  select data,version into v_data,v_version from private.inventory_state where id=true and branch_id=p_branch_id;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=v_name;
  if v_user is null then
    select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=v_name;
  end if;
  if v_user is null or coalesce(v_user->>'pin','')<>p_pin_hash or coalesce((v_user->>'active')::boolean,false) is not true then
    update private.inventory_login_failures set failures=case when failures>=4 then 0 else failures+1 end,
      blocked_until=case when failures>=4 then now()+interval '60 seconds' else null end where branch_id=p_branch_id and username=v_name;
    return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้หรือรหัสไม่ถูกต้อง');
  end if;
  delete from private.inventory_login_failures where branch_id=p_branch_id and username=v_name;
  v_token:=encode(extensions.gen_random_bytes(32),'hex');
  insert into private.inventory_sessions(token_hash,username,branch_id,expires_at) values(encode(extensions.digest(v_token,'sha256'),'hex'),v_name,p_branch_id,now()+interval '7 days');
  return jsonb_build_object('ok',true,'token',v_token,'state',public.api_safe_state(v_data),'me',v_user-'pin','version',v_version,'branch',v_branch);
end $$;

create or replace function public.api_login(p_name text,p_pin_hash text)
returns jsonb language sql security definer set search_path=''
as $$
  select public.api_branch_login('e735a3bf-8a74-4a8c-9e9b-7af778e91234'::uuid,p_name,p_pin_hash);
$$;

create or replace function public.api_branch_create(p_token text,p_name text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_username text; v_branch_id uuid; v_name text:=trim(coalesce(p_name,'')); v_id uuid; v_roles jsonb;
begin
  select username,branch_id into v_username,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_username is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  if not exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_username)) then return jsonb_build_object('ok',false,'error','เฉพาะ kiangkai ผู้ดูแลหลักเท่านั้นที่เพิ่มสาขาได้'); end if;
  if length(v_name)<2 or length(v_name)>80 then return jsonb_build_object('ok',false,'error','ชื่อสาขาต้องยาว 2–80 ตัวอักษร'); end if;
  if exists(select 1 from private.inventory_branches where lower(name)=lower(v_name)) then return jsonb_build_object('ok',false,'error','มีชื่อสาขานี้แล้ว'); end if;
  v_id:=extensions.gen_random_uuid();
  select data->'roles' into v_roles from private.inventory_state where id=true and branch_id=v_branch_id;
  insert into private.inventory_branches(id,name,created_by) values(v_id,v_name,v_username);
  insert into private.inventory_state(id,branch_id,data,version) values(true,v_id,jsonb_build_object('users','[]'::jsonb,'products','[]'::jsonb,'log','[]'::jsonb,'roles',coalesce(v_roles,'{}'::jsonb),'categories','[]'::jsonb,'units','[]'::jsonb),1);
  return jsonb_build_object('ok',true,'branch',jsonb_build_object('id',v_id,'name',v_name));
end $$;

-- Scoped function bodies are generated from the current, permission-checked single-branch functions.


-- Branch-scoped versions of the existing authenticated RPCs.
create or replace function public.api_get_state(p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_name text; v_data jsonb; v_user jsonb; v_version bigint;
begin
  select username,branch_id into v_name,v_branch_id from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id=true and branch_id=v_branch_id;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
    select account into v_user from private.inventory_global_admin where id=true;
  else
    select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
  end if;
  if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data), 'me', v_user - 'pin', 'version', v_version, 'branch', (select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
end;
$$;

create or replace function public.api_set_theme(p_token text, p_theme text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_name text; v_version bigint;
begin
  select username,branch_id into v_name,v_branch_id from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  if coalesce(p_theme, '') not in ('sakura','matcha','ocean','lavender','peach','lemon','mint','grape','coral','ramune','taro','nori','midnight') then
    return jsonb_build_object('ok', false, 'error', 'ไม่พบธีมที่เลือก');
  end if;
  update private.inventory_state
    set data = jsonb_set(data, '{theme}', to_jsonb(p_theme), true), version = version + 1, updated_at = now()
    where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok', true, 'version', v_version);
end;
$$;

create or replace function public.api_sync(p_token text, p_base jsonb, p_data jsonb)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_name text; v_data jsonb; v_user jsonb; v_version bigint; v_next jsonb; v_users jsonb;
  v_perm jsonb; v_log jsonb; v_add jsonb; v_products_changed boolean;
  v_users_changed boolean; v_lists_changed boolean;
begin
  select username,branch_id into v_name,v_branch_id from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id=true and branch_id=v_branch_id for update;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
    select account into v_user from private.inventory_global_admin where id=true;
  else
    select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
  end if;
  if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  v_perm := coalesce(v_user->'permissions', '{}'::jsonb);
  v_products_changed := coalesce(p_base->'products', '[]'::jsonb) is distinct from coalesce(p_data->'products', '[]'::jsonb);
  v_users_changed := coalesce(p_base->'users', '[]'::jsonb) is distinct from coalesce(p_data->'users', '[]'::jsonb);
  v_lists_changed := coalesce(p_base->'roles', '{}'::jsonb) is distinct from coalesce(p_data->'roles', '{}'::jsonb)
    or coalesce(p_base->'categories', '[]'::jsonb) is distinct from coalesce(p_data->'categories', '[]'::jsonb)
    or coalesce(p_base->'units', '[]'::jsonb) is distinct from coalesce(p_data->'units', '[]'::jsonb);

  if v_users_changed and (
    exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) where lower(value->>'name')=lower((select account->>'name' from private.inventory_global_admin where id=true)))
    or exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) group by lower(value->>'name') having count(*)>1)
  ) then
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้ซ้ำหรือสงวนไว้สำหรับผู้ดูแลหลัก');
  end if;

  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_products_changed and not coalesce((v_perm->>'editStock')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการสต็อก');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'manageUsers')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการผู้ใช้');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'deleteUsers')::boolean, false) and exists (
    select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) oldu
    where not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name')
  ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบผู้ใช้'); end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'managePermissions')::boolean, false) then
    if exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      join jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu on oldu->>'name'=newu->>'name'
      where coalesce(oldu->>'role','') is distinct from coalesce(newu->>'role','')
         or coalesce(oldu->'permissions','{}'::jsonb) is distinct from coalesce(newu->'permissions','{}'::jsonb)
    ) or exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu where oldu->>'name'=newu->>'name')
        and (
          newu->>'role' in ('admin','supervisor')
          or coalesce(newu->'permissions','{}'::jsonb) is distinct from
            case newu->>'role'
              when 'admin' then '{"editStock":true,"manageLists":true,"manageUsers":true,"deleteUsers":true,"deleteStock":true,"managePermissions":true}'::jsonb
              when 'supervisor' then '{"editStock":true,"manageLists":true,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
              when 'staff' then '{"editStock":true,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
              else '{"editStock":false,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
            end
        )
    ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์กำหนดตำแหน่งหรือสิทธิ์'); end if;
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_lists_changed and not coalesce((v_perm->>'manageLists')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์แก้ไขรายการ');
  end if;

  -- ป้องกันการเขียนทับการแก้ไขของอีกเครื่องในหมวดเดียวกัน
  if v_products_changed and v_data->'products' is distinct from p_base->'products' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขสต็อกจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่แล้วทำรายการอีกครั้ง');
  end if;
  if v_users_changed and public.api_safe_state(v_data)->'users' is distinct from p_base->'users' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขผู้ใช้จากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;
  if v_lists_changed and (v_data->'roles' is distinct from p_base->'roles' or v_data->'categories' is distinct from p_base->'categories' or v_data->'units' is distinct from p_base->'units') then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขรายการจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;

  v_next := v_data;
  if v_products_changed then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'deleteStock')::boolean, false) then
      if exists(select 1 from jsonb_array_elements(v_data->'products') oldp where not exists (
        select 1 from jsonb_array_elements(coalesce(p_data->'products','[]'::jsonb)) newp where newp->>'id' = oldp->>'id'
      )) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบวัตถุดิบ'); end if;
    end if;
    v_next := jsonb_set(v_next, '{products}', coalesce(p_data->'products', '[]'::jsonb));
  end if;
  if v_users_changed then
    if exists(select 1 from jsonb_array_elements(v_data->'users') oldu where coalesce((oldu->>'owner')::boolean,false)
      and not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name' and newu->>'role'=oldu->>'role' and coalesce((newu->>'active')::boolean,false))) then
      return jsonb_build_object('ok', false, 'error', 'ไม่สามารถปิดหรือลบบัญชีผู้ดูแลหลักได้');
    end if;
    if not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u where u->>'role'='admin' and coalesce((u->>'active')::boolean,false)) and coalesce((v_user->>'owner')::boolean,false) is not true then
      return jsonb_build_object('ok', false, 'error', 'ต้องมีผู้ดูแลที่เปิดใช้งานอย่างน้อยหนึ่งบัญชี');
    end if;
    select coalesce(jsonb_agg(
      case when newu.user_data ? 'pin' then newu.user_data else newu.user_data || jsonb_build_object('pin', oldu.user_data->'pin') end order by newu.position
    ), '[]'::jsonb) into v_users
    from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) with ordinality as newu(user_data, position)
    left join jsonb_array_elements(v_data->'users') as oldu(user_data) on oldu.user_data->>'name'=newu.user_data->>'name';
    if exists(select 1 from jsonb_array_elements(v_users) as u(user_data) where coalesce(u.user_data->>'pin','') !~ '^[0-9a-f]{64}$') then
      return jsonb_build_object('ok', false, 'error', 'บัญชีผู้ใช้ต้องมีรหัส 6 หลักก่อนบันทึก');
    end if;
    v_next := jsonb_set(v_next, '{users}', v_users);
  end if;
  if v_lists_changed then
    v_next := jsonb_set(v_next, '{roles}', coalesce(p_data->'roles','{}'::jsonb));
    v_next := jsonb_set(v_next, '{categories}', coalesce(p_data->'categories','[]'::jsonb));
    v_next := jsonb_set(v_next, '{units}', coalesce(p_data->'units','[]'::jsonb));
  end if;

  -- ประวัติเป็นข้อมูลเพิ่มต่อท้าย ไม่ลบประวัติที่อุปกรณ์อื่นบันทึกไว้
  select coalesce(jsonb_agg(entry), '[]'::jsonb) into v_add
    from jsonb_array_elements(coalesce(p_data->'log','[]'::jsonb)) entry
    where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'log','[]'::jsonb)) oldentry where oldentry = entry);
  if jsonb_array_length(v_add) > 0 then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'editStock')::boolean, false) then
      return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์บันทึกประวัติสต็อก');
    end if;
    select coalesce(jsonb_agg((entry - 'user' - 'role') || jsonb_build_object('user', v_name, 'role', coalesce(v_data->'roles'->>(v_user->>'role'), v_user->>'role', 'พนักงานคลัง')) order by (entry->>'ts')::numeric desc), '[]'::jsonb)
      into v_log from jsonb_array_elements(v_add) entry;
    select coalesce(jsonb_agg(item order by ord), '[]'::jsonb) into v_log
      from (select item, ord from jsonb_array_elements(v_log || coalesce(v_data->'log','[]'::jsonb)) with ordinality as x(item,ord) order by ord limit 500) recent;
    v_next := jsonb_set(v_next, '{log}', v_log);
  end if;

  update private.inventory_state set data = v_next, version = version + 1, updated_at = now() where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_next), 'version', v_version);
end;
$$;

create or replace function public.api_reset_data(p_token text, p_scope text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_name text;
  v_data jsonb;
  v_user jsonb;
  v_version bigint;
begin
  select username, branch_id into v_name, v_branch_id
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();
  if v_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select data into v_data from private.inventory_state where id=true and branch_id=v_branch_id for update;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
    select account into v_user from private.inventory_global_admin where id=true;
  else
    select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
  end if;
  if v_user is null or (
    coalesce((v_user->>'owner')::boolean, false) is not true
    and lower(v_user->>'name') <> 'kiangkai'
    and coalesce(v_user->>'role', '') <> 'admin'
    and coalesce((v_user->'permissions'->>'resetData')::boolean, false) is not true
  ) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์รีเซ็ตข้อมูล');
  end if;
  if p_scope is null or p_scope not in ('products', 'history', 'users', 'all') then
    return jsonb_build_object('ok', false, 'error', 'ขอบเขตการรีเซ็ตไม่ถูกต้อง');
  end if;

  if p_scope in ('products', 'all') then
    v_data := jsonb_set(v_data, '{products}', '[]'::jsonb);
  end if;
  if p_scope in ('history', 'all', 'users') then
    v_data := jsonb_set(v_data, '{log}', '[]'::jsonb);
  end if;
  if p_scope = 'users' then
    select coalesce(jsonb_agg(value), '[]'::jsonb) into v_user
    from jsonb_array_elements(v_data->'users') value
    where coalesce(value->>'role','')='admin' and coalesce((value->>'active')::boolean,false);
    v_data := jsonb_set(v_data, '{users}', v_user);
  end if;

  v_data := jsonb_set(v_data, '{lastReset}', jsonb_build_object(
    'scope', p_scope,
    'user', v_name,
    'ts', floor(extract(epoch from clock_timestamp()) * 1000)::bigint
  ), true);

  update private.inventory_state
  set data = v_data, version = version + 1, updated_at = now()
  where id=true and branch_id=v_branch_id
  returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data), 'version', v_version);
end;
$$;

create or replace function public.api_presence_tick(p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_username text;
  v_users jsonb;
begin
  update private.inventory_sessions
    set last_seen = now()
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
      and expires_at > now()
    returning username,branch_id into v_username,v_branch_id;
  if v_username is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;
  select coalesce(jsonb_agg(active.username order by active.username), '[]'::jsonb)
    into v_users
    from (
      select distinct username
      from private.inventory_sessions
      where branch_id=v_branch_id and expires_at > now() and last_seen > now() - interval '50 seconds'
    ) active;
  return jsonb_build_object('ok', true, 'users', v_users);
end;
$$;


create or replace function public.api_bootstrap_status()
returns jsonb language sql security definer set search_path=''
as $$ select jsonb_build_object('ready',true,'firstLogin',coalesce((account->>'must')::boolean,false)) from private.inventory_global_admin where id=true; $$;

create or replace function public.api_change_pin(p_token text,p_old_hash text,p_new_hash text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_name text; v_branch_id uuid; v_data jsonb; v_user jsonb; v_users jsonb; v_version bigint;
begin
  if coalesce(p_new_hash,'') !~ '^[0-9a-f]{64}$' then return jsonb_build_object('ok',false,'error','รหัสใหม่ไม่ถูกต้อง'); end if;
  select username,branch_id into v_name,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name) for update;
  if v_user is not null then
    if coalesce((v_user->>'must')::boolean,false) is false and v_user->>'pin'<>p_old_hash then return jsonb_build_object('ok',false,'error','รหัสปัจจุบันไม่ถูกต้อง'); end if;
    update private.inventory_global_admin set account=account||jsonb_build_object('pin',p_new_hash,'must',false),updated_at=now() where id=true;
    select data,version into v_data,v_version from private.inventory_state where id=true and branch_id=v_branch_id;
    return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',(select account-'pin' from private.inventory_global_admin where id=true),'version',v_version,'branch',(select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
  end if;
  select data into v_data from private.inventory_state where id=true and branch_id=v_branch_id for update;
  select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
  if v_user is null or (coalesce((v_user->>'must')::boolean,false) is false and v_user->>'pin'<>p_old_hash) then return jsonb_build_object('ok',false,'error','รหัสปัจจุบันไม่ถูกต้อง'); end if;
  select coalesce(jsonb_agg(case when lower(value->>'name')=lower(v_name) then value||jsonb_build_object('pin',p_new_hash,'must',false) else value end),'[]'::jsonb) into v_users from jsonb_array_elements(v_data->'users') value;
  v_data:=jsonb_set(v_data,'{users}',v_users);
  update private.inventory_state set data=v_data,version=version+1,updated_at=now() where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',(select value-'pin' from jsonb_array_elements(v_users) value where lower(value->>'name')=lower(v_name)),'version',v_version,'branch',(select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
end $$;

create or replace function public.api_update_owner_account(p_token text,p_old_hash text,p_new_name text,p_new_hash text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_old text; v_branch_id uuid; v_name text:=lower(trim(coalesce(p_new_name,''))); v_user jsonb; v_data jsonb; v_version bigint;
begin
  if v_name='' or length(v_name)<3 or length(v_name)>20 or coalesce(p_old_hash,'') !~ '^[0-9a-f]{64}$' or coalesce(p_new_hash,'') !~ '^[0-9a-f]{64}$' then return jsonb_build_object('ok',false,'error','ข้อมูลบัญชีไม่ถูกต้อง'); end if;
  select username,branch_id into v_old,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_old is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_old) for update;
  if v_user is null then return jsonb_build_object('ok',false,'error','เฉพาะผู้ดูแลหลักเท่านั้น'); end if;
  if v_user->>'pin'<>p_old_hash then return jsonb_build_object('ok',false,'error','รหัสปัจจุบันไม่ถูกต้อง'); end if;
  if exists(select 1 from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) u where lower(u->>'name')=v_name) then return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้นี้มีคนใช้แล้ว'); end if;
  update private.inventory_global_admin set account=account||jsonb_build_object('name',v_name,'pin',p_new_hash,'must',false),updated_at=now() where id=true;
  update private.inventory_sessions set username=v_name where username=v_old;
  delete from private.inventory_login_failures where username in(v_old,v_name);
  select data,version into v_data,v_version from private.inventory_state where id=true and branch_id=v_branch_id;
  select account into v_user from private.inventory_global_admin where id=true;
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',v_user-'pin','version',v_version,'branch',(select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
end $$;

create or replace function public.api_update_username(p_token text,p_old_hash text,p_new_name text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_old text; v_branch_id uuid; v_name text:=lower(trim(coalesce(p_new_name,''))); v_data jsonb; v_user jsonb; v_users jsonb; v_version bigint;
begin
  if v_name='' or length(v_name)<3 or length(v_name)>20 or coalesce(p_old_hash,'') !~ '^[0-9a-f]{64}$' then return jsonb_build_object('ok',false,'error','ข้อมูลบัญชีไม่ถูกต้อง'); end if;
  select username,branch_id into v_old,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_old is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_old) for update;
  if v_user is not null then
    if v_user->>'pin'<>p_old_hash then return jsonb_build_object('ok',false,'error','รหัสปัจจุบันไม่ถูกต้อง'); end if;
    if exists(select 1 from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) u where lower(u->>'name')=v_name) then return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้นี้มีคนใช้แล้ว'); end if;
    update private.inventory_global_admin set account=account||jsonb_build_object('name',v_name),updated_at=now() where id=true;
    update private.inventory_sessions set username=v_name where username=v_old;
    delete from private.inventory_login_failures where username in(v_old,v_name);
    select data,version into v_data,v_version from private.inventory_state where id=true and branch_id=v_branch_id;
    select account into v_user from private.inventory_global_admin where id=true;
    return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',v_user-'pin','version',v_version,'branch',(select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
  end if;
  select data into v_data from private.inventory_state where id=true and branch_id=v_branch_id for update;
  select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_old);
  if v_user is null or (coalesce((v_user->>'owner')::boolean,false) is not true and coalesce(v_user->>'role','')<>'admin') then return jsonb_build_object('ok',false,'error','เฉพาะผู้ดูแลระบบเท่านั้นที่แก้ไขชื่อได้'); end if;
  if v_user->>'pin'<>p_old_hash then return jsonb_build_object('ok',false,'error','รหัสปัจจุบันไม่ถูกต้อง'); end if;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=v_name) or exists(select 1 from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) u where lower(u->>'name')=v_name and s.branch_id<>v_branch_id) or exists(select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) u where lower(u->>'name')=v_name and lower(u->>'name')<>lower(v_old)) then return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้นี้มีคนใช้แล้ว'); end if;
  select coalesce(jsonb_agg(case when lower(value->>'name')=lower(v_old) then value||jsonb_build_object('name',v_name) else value end),'[]'::jsonb) into v_users from jsonb_array_elements(v_data->'users') value;
  v_data:=jsonb_set(v_data,'{users}',v_users);
  update private.inventory_state set data=v_data,version=version+1,updated_at=now() where id=true and branch_id=v_branch_id returning version into v_version;
  update private.inventory_sessions set username=v_name where username=v_old and branch_id=v_branch_id;
  delete from private.inventory_login_failures where username in(v_old,v_name) and branch_id=v_branch_id;
  select value into v_user from jsonb_array_elements(v_users) where lower(value->>'name')=v_name;
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',v_user-'pin','version',v_version,'branch',(select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
end $$;

create or replace function public.api_storage_usage(p_token text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_name text; v_branch_id uuid; v_user jsonb; v_used bigint; v_quota bigint:=500::bigint*1024*1024;
begin
  select username,branch_id into v_name,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name);
  if v_user is null then
    select value into v_user from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) where s.id=true and s.branch_id=v_branch_id and lower(value->>'name')=lower(v_name);
  end if;
  if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true or (coalesce((v_user->>'owner')::boolean,false) is not true and coalesce(v_user->>'role','')<>'admin') then return jsonb_build_object('ok',false,'error','เฉพาะผู้ดูแลหลักหรือผู้ดูแลระบบเท่านั้นที่ดูข้อมูลนี้ได้'); end if;
  v_used:=pg_catalog.pg_database_size(pg_catalog.current_database());
  return jsonb_build_object('ok',true,'usedBytes',v_used,'quotaBytes',v_quota,'remainingBytes',greatest(v_quota-v_used,0),'usedPercent',round(v_used::numeric*100/v_quota,2),'checkedAt',now(),'quotaPlan','Free');
end $$;

revoke all on function public.api_bootstrap_status() from public,anon,authenticated;
revoke all on function public.api_login(text,text) from public,anon,authenticated;
revoke all on function public.api_branch_list() from public,anon,authenticated;
revoke all on function public.api_branch_login(uuid,text,text) from public,anon,authenticated;
revoke all on function public.api_branch_create(text,text) from public,anon,authenticated;
revoke all on function public.api_get_state(text) from public,anon,authenticated;
revoke all on function public.api_set_theme(text,text) from public,anon,authenticated;
revoke all on function public.api_sync(text,jsonb,jsonb) from public,anon,authenticated;
revoke all on function public.api_reset_data(text,text) from public,anon,authenticated;
revoke all on function public.api_change_pin(text,text,text) from public,anon,authenticated;
revoke all on function public.api_update_owner_account(text,text,text,text) from public,anon,authenticated;
revoke all on function public.api_update_username(text,text,text) from public,anon,authenticated;
revoke all on function public.api_logout(text) from public,anon,authenticated;
revoke all on function public.api_presence_tick(text) from public,anon,authenticated;
revoke all on function public.api_storage_usage(text) from public,anon,authenticated;
grant execute on function public.api_bootstrap_status() to anon,authenticated;
grant execute on function public.api_login(text,text) to anon,authenticated;
grant execute on function public.api_branch_list() to anon,authenticated;
grant execute on function public.api_branch_login(uuid,text,text) to anon,authenticated;
grant execute on function public.api_branch_create(text,text) to anon,authenticated;
grant execute on function public.api_get_state(text) to anon,authenticated;
grant execute on function public.api_set_theme(text,text) to anon,authenticated;
grant execute on function public.api_sync(text,jsonb,jsonb) to anon,authenticated;
grant execute on function public.api_reset_data(text,text) to anon,authenticated;
grant execute on function public.api_change_pin(text,text,text) to anon,authenticated;
grant execute on function public.api_update_owner_account(text,text,text,text) to anon,authenticated;
grant execute on function public.api_update_username(text,text,text) to anon,authenticated;
grant execute on function public.api_logout(text) to anon,authenticated;
grant execute on function public.api_presence_tick(text) to anon,authenticated;
grant execute on function public.api_storage_usage(text) to anon,authenticated;
notify pgrst,'reload schema';
commit;

--

--

-- Branch manager permission and in-app branch switching.

begin;

alter table private.inventory_sessions add column if not exists manager_origin_branch_id uuid;

create or replace function public.api_branch_switch(p_token text,p_branch_id uuid,p_pin_hash text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_name text; v_branch_id uuid; v_origin uuid; v_auth_branch uuid; v_user jsonb; v_data jsonb; v_version bigint; v_branch jsonb; v_global boolean:=false; v_fail private.inventory_login_failures%rowtype;
begin
  select username,branch_id,manager_origin_branch_id into v_name,v_branch_id,v_origin from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now() for update;
  if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select jsonb_build_object('id',id,'name',name) into v_branch from private.inventory_branches where id=p_branch_id and active;
  if v_branch is null then return jsonb_build_object('ok',false,'error','ไม่พบสาขาที่เลือก'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name);
  if v_user is not null then v_global:=true; v_auth_branch:=v_branch_id; else
    v_auth_branch:=coalesce(v_origin,v_branch_id);
    select value into v_user from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) where s.id=true and s.branch_id=v_auth_branch and lower(value->>'name')=lower(v_name);
  end if;
  insert into private.inventory_login_failures(branch_id,username) values(v_auth_branch,lower(v_name)) on conflict(branch_id,username) do nothing;
  select * into v_fail from private.inventory_login_failures where branch_id=v_auth_branch and username=lower(v_name) for update;
  if v_fail.blocked_until is not null and v_fail.blocked_until>now() then return jsonb_build_object('ok',false,'error','ลองยืนยันรหัสหลายครั้ง กรุณารอสักครู่'); end if;
  if not v_global and coalesce(v_user->>'role','')<>'admin' and coalesce((v_user->'permissions'->>'manageBranches')::boolean,false) is not true then return jsonb_build_object('ok',false,'error','บัญชีนี้ไม่มีสิทธิ์จัดการสาขา'); end if;
  if v_user is null or coalesce(v_user->>'pin','')<>coalesce(p_pin_hash,'') or coalesce((v_user->>'active')::boolean,false) is not true then
    update private.inventory_login_failures set failures=case when failures>=4 then 0 else failures+1 end,blocked_until=case when failures>=4 then now()+interval '60 seconds' else null end where branch_id=v_auth_branch and username=lower(v_name);
    return jsonb_build_object('ok',false,'error','รหัสผ่านไม่ถูกต้อง หรือบัญชีถูกปิดใช้งาน');
  end if;
  delete from private.inventory_login_failures where branch_id=v_auth_branch and username=lower(v_name);
  select data,version into v_data,v_version from private.inventory_state where id=true and branch_id=p_branch_id;
  if v_global or p_branch_id=v_auth_branch then v_origin:=null; else v_origin:=v_auth_branch; v_user:=v_user||jsonb_build_object('role','admin','permissions',jsonb_build_object('editStock',true,'manageLists',true,'manageUsers',true,'deleteUsers',true,'deleteStock',true,'managePermissions',true,'resetData',true,'manageBranches',true),'branchManagerAccess',true,'owner',true); end if;
  update private.inventory_sessions set branch_id=p_branch_id,manager_origin_branch_id=v_origin,expires_at=now()+interval '7 days' where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex');
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',v_user-'pin','version',v_version,'branch',v_branch);
end $$;

create or replace function public.api_branch_create(p_token text,p_name text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_username text; v_branch_id uuid; v_origin uuid; v_account jsonb; v_name text:=trim(coalesce(p_name,'')); v_id uuid; v_roles jsonb;
begin
  select username,branch_id,manager_origin_branch_id into v_username,v_branch_id,v_origin from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_username is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_account from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_username);
  if v_account is null then
    select value into v_account from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) where s.id=true and s.branch_id=coalesce(v_origin,v_branch_id) and lower(value->>'name')=lower(v_username);
    if v_account is null or coalesce((v_account->>'active')::boolean,false) is not true or (coalesce(v_account->>'role','')<>'admin' and coalesce((v_account->'permissions'->>'manageBranches')::boolean,false) is not true) then return jsonb_build_object('ok',false,'error','บัญชีนี้ไม่มีสิทธิ์จัดการสาขา'); end if;
  end if;
  if length(v_name)<2 or length(v_name)>80 then return jsonb_build_object('ok',false,'error','ชื่อสาขาต้องยาว 2–80 ตัวอักษร'); end if;
  if exists(select 1 from private.inventory_branches where lower(name)=lower(v_name)) then return jsonb_build_object('ok',false,'error','มีชื่อสาขานี้แล้ว'); end if;
  v_id:=extensions.gen_random_uuid();
  select data->'roles' into v_roles from private.inventory_state where id=true and branch_id=v_branch_id;
  insert into private.inventory_branches(id,name,created_by) values(v_id,v_name,v_username);
  insert into private.inventory_state(id,branch_id,data,version) values(true,v_id,jsonb_build_object('users','[]'::jsonb,'products','[]'::jsonb,'log','[]'::jsonb,'roles',coalesce(v_roles,'{}'::jsonb),'categories','[]'::jsonb,'units','[]'::jsonb),1);
  return jsonb_build_object('ok',true,'branch',jsonb_build_object('id',v_id,'name',v_name));
end $$;

create or replace function public.api_get_state(p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid;
  v_name text; v_data jsonb; v_user jsonb; v_version bigint; v_origin uuid;
begin
  select username,branch_id,manager_origin_branch_id into v_name,v_branch_id,v_origin from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id=true and branch_id=v_branch_id;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
     select account into v_user from private.inventory_global_admin where id=true;
   elsif v_origin is not null then
     select value into v_user from private.inventory_state src cross join lateral jsonb_array_elements(coalesce(src.data->'users','[]'::jsonb)) where src.id=true and src.branch_id=v_origin and lower(value->>'name')=lower(v_name);
     if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true or (coalesce(v_user->>'role','')<>'admin' and coalesce((v_user->'permissions'->>'manageBranches')::boolean,false) is not true) then return jsonb_build_object('ok',false,'error','สิทธิ์จัดการสาขาถูกยกเลิก กรุณาเข้าสู่ระบบใหม่'); end if;
     v_user:=v_user||jsonb_build_object('role','admin','permissions',jsonb_build_object('editStock',true,'manageLists',true,'manageUsers',true,'deleteUsers',true,'deleteStock',true,'managePermissions',true,'resetData',true,'manageBranches',true),'branchManagerAccess',true,'owner',true);
   else
     select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
   end if;
   if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data), 'me', v_user - 'pin', 'version', v_version, 'branch', (select jsonb_build_object('id',id,'name',name) from private.inventory_branches where id=v_branch_id));
end;
$$;

create or replace function public.api_sync(p_token text, p_base jsonb, p_data jsonb)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid; v_origin uuid;
  v_name text; v_data jsonb; v_user jsonb; v_version bigint; v_next jsonb; v_users jsonb;
  v_perm jsonb; v_log jsonb; v_add jsonb; v_products_changed boolean;
  v_users_changed boolean; v_lists_changed boolean;
begin
  select username,branch_id,manager_origin_branch_id into v_name,v_branch_id,v_origin from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id=true and branch_id=v_branch_id for update;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
     select account into v_user from private.inventory_global_admin where id=true;
   elsif v_origin is not null then
     select value into v_user from private.inventory_state src cross join lateral jsonb_array_elements(coalesce(src.data->'users','[]'::jsonb)) where src.id=true and src.branch_id=v_origin and lower(value->>'name')=lower(v_name);
     if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true or (coalesce(v_user->>'role','')<>'admin' and coalesce((v_user->'permissions'->>'manageBranches')::boolean,false) is not true) then return jsonb_build_object('ok',false,'error','สิทธิ์จัดการสาขาถูกยกเลิก กรุณาเข้าสู่ระบบใหม่'); end if;
     v_user:=v_user||jsonb_build_object('role','admin','permissions',jsonb_build_object('editStock',true,'manageLists',true,'manageUsers',true,'deleteUsers',true,'deleteStock',true,'managePermissions',true,'resetData',true,'manageBranches',true),'branchManagerAccess',true,'owner',true);
   else
     select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
   end if;
   if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  v_perm := coalesce(v_user->'permissions', '{}'::jsonb);
  v_products_changed := coalesce(p_base->'products', '[]'::jsonb) is distinct from coalesce(p_data->'products', '[]'::jsonb);
  v_users_changed := coalesce(p_base->'users', '[]'::jsonb) is distinct from coalesce(p_data->'users', '[]'::jsonb);
  v_lists_changed := coalesce(p_base->'roles', '{}'::jsonb) is distinct from coalesce(p_data->'roles', '{}'::jsonb)
    or coalesce(p_base->'categories', '[]'::jsonb) is distinct from coalesce(p_data->'categories', '[]'::jsonb)
    or coalesce(p_base->'units', '[]'::jsonb) is distinct from coalesce(p_data->'units', '[]'::jsonb);

  if v_users_changed and (
    exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) where lower(value->>'name')=lower((select account->>'name' from private.inventory_global_admin where id=true)))
    or exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) group by lower(value->>'name') having count(*)>1)
  ) then
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้ซ้ำหรือสงวนไว้สำหรับผู้ดูแลหลัก');
  end if;

  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_products_changed and not coalesce((v_perm->>'editStock')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการสต็อก');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'manageUsers')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการผู้ใช้');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'deleteUsers')::boolean, false) and exists (
    select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) oldu
    where not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name')
  ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบผู้ใช้'); end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'managePermissions')::boolean, false) then
    if exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      join jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu on oldu->>'name'=newu->>'name'
      where coalesce(oldu->>'role','') is distinct from coalesce(newu->>'role','')
         or coalesce(oldu->'permissions','{}'::jsonb) is distinct from coalesce(newu->'permissions','{}'::jsonb)
    ) or exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu where oldu->>'name'=newu->>'name')
        and (
          newu->>'role' in ('admin','supervisor')
          or coalesce(newu->'permissions','{}'::jsonb) is distinct from
            case newu->>'role'
              when 'admin' then '{"editStock":true,"manageLists":true,"manageUsers":true,"deleteUsers":true,"deleteStock":true,"managePermissions":true,"manageBranches":true}'::jsonb
              when 'supervisor' then '{"editStock":true,"manageLists":true,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false,"manageBranches":false}'::jsonb
              when 'staff' then '{"editStock":true,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false}'::jsonb
              else '{"editStock":false,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false,"manageBranches":false}'::jsonb
            end
        )
    ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์กำหนดตำแหน่งหรือสิทธิ์'); end if;
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_lists_changed and not coalesce((v_perm->>'manageLists')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์แก้ไขรายการ');
  end if;

  -- ป้องกันการเขียนทับการแก้ไขของอีกเครื่องในหมวดเดียวกัน
  if v_products_changed and v_data->'products' is distinct from p_base->'products' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขสต็อกจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่แล้วทำรายการอีกครั้ง');
  end if;
  if v_users_changed and public.api_safe_state(v_data)->'users' is distinct from p_base->'users' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขผู้ใช้จากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;
  if v_lists_changed and (v_data->'roles' is distinct from p_base->'roles' or v_data->'categories' is distinct from p_base->'categories' or v_data->'units' is distinct from p_base->'units') then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขรายการจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;

  v_next := v_data;
  if v_products_changed then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'deleteStock')::boolean, false) then
      if exists(select 1 from jsonb_array_elements(v_data->'products') oldp where not exists (
        select 1 from jsonb_array_elements(coalesce(p_data->'products','[]'::jsonb)) newp where newp->>'id' = oldp->>'id'
      )) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบวัตถุดิบ'); end if;
    end if;
    v_next := jsonb_set(v_next, '{products}', coalesce(p_data->'products', '[]'::jsonb));
  end if;
  if v_users_changed then
    if exists(select 1 from jsonb_array_elements(v_data->'users') oldu where coalesce((oldu->>'owner')::boolean,false)
      and not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name' and newu->>'role'=oldu->>'role' and coalesce((newu->>'active')::boolean,false))) then
      return jsonb_build_object('ok', false, 'error', 'ไม่สามารถปิดหรือลบบัญชีผู้ดูแลหลักได้');
    end if;
    if not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u where u->>'role'='admin' and coalesce((u->>'active')::boolean,false)) and coalesce((v_user->>'owner')::boolean,false) is not true then
      return jsonb_build_object('ok', false, 'error', 'ต้องมีผู้ดูแลที่เปิดใช้งานอย่างน้อยหนึ่งบัญชี');
    end if;
    select coalesce(jsonb_agg(
      case when newu.user_data ? 'pin' then newu.user_data else newu.user_data || jsonb_build_object('pin', oldu.user_data->'pin') end order by newu.position
    ), '[]'::jsonb) into v_users
    from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) with ordinality as newu(user_data, position)
    left join jsonb_array_elements(v_data->'users') as oldu(user_data) on oldu.user_data->>'name'=newu.user_data->>'name';
    if exists(select 1 from jsonb_array_elements(v_users) as u(user_data) where coalesce(u.user_data->>'pin','') !~ '^[0-9a-f]{64}$') then
      return jsonb_build_object('ok', false, 'error', 'บัญชีผู้ใช้ต้องมีรหัส 6 หลักก่อนบันทึก');
    end if;
    v_next := jsonb_set(v_next, '{users}', v_users);
  end if;
  if v_lists_changed then
    v_next := jsonb_set(v_next, '{roles}', coalesce(p_data->'roles','{}'::jsonb));
    v_next := jsonb_set(v_next, '{categories}', coalesce(p_data->'categories','[]'::jsonb));
    v_next := jsonb_set(v_next, '{units}', coalesce(p_data->'units','[]'::jsonb));
  end if;

  -- ประวัติเป็นข้อมูลเพิ่มต่อท้าย ไม่ลบประวัติที่อุปกรณ์อื่นบันทึกไว้
  select coalesce(jsonb_agg(entry), '[]'::jsonb) into v_add
    from jsonb_array_elements(coalesce(p_data->'log','[]'::jsonb)) entry
    where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'log','[]'::jsonb)) oldentry where oldentry = entry);
  if jsonb_array_length(v_add) > 0 then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'editStock')::boolean, false) then
      return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์บันทึกประวัติสต็อก');
    end if;
    select coalesce(jsonb_agg((entry - 'user' - 'role') || jsonb_build_object('user', v_name, 'role', coalesce(v_data->'roles'->>(v_user->>'role'), v_user->>'role', 'พนักงานคลัง')) order by (entry->>'ts')::numeric desc), '[]'::jsonb)
      into v_log from jsonb_array_elements(v_add) entry;
    select coalesce(jsonb_agg(item order by ord), '[]'::jsonb) into v_log
      from (select item, ord from jsonb_array_elements(v_log || coalesce(v_data->'log','[]'::jsonb)) with ordinality as x(item,ord) order by ord limit 500) recent;
    v_next := jsonb_set(v_next, '{log}', v_log);
  end if;

  update private.inventory_state set data = v_next, version = version + 1, updated_at = now() where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_next), 'version', v_version);
end;
$$;

create or replace function public.api_reset_data(p_token text, p_scope text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid; v_origin uuid;
  v_name text;
  v_data jsonb;
  v_user jsonb;
  v_version bigint;
begin
  select username, branch_id, manager_origin_branch_id into v_name, v_branch_id, v_origin
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();
  if v_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select data into v_data from private.inventory_state where id=true and branch_id=v_branch_id for update;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
     select account into v_user from private.inventory_global_admin where id=true;
   elsif v_origin is not null then
     select value into v_user from private.inventory_state src cross join lateral jsonb_array_elements(coalesce(src.data->'users','[]'::jsonb)) where src.id=true and src.branch_id=v_origin and lower(value->>'name')=lower(v_name);
     if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true or (coalesce(v_user->>'role','')<>'admin' and coalesce((v_user->'permissions'->>'manageBranches')::boolean,false) is not true) then return jsonb_build_object('ok',false,'error','สิทธิ์จัดการสาขาถูกยกเลิก กรุณาเข้าสู่ระบบใหม่'); end if;
     v_user:=v_user||jsonb_build_object('role','admin','permissions',jsonb_build_object('resetData',true));
   else
     select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
   end if;
   if v_user is null or (
    coalesce((v_user->>'owner')::boolean, false) is not true
    and lower(v_user->>'name') <> 'kiangkai'
    and coalesce(v_user->>'role', '') <> 'admin'
    and coalesce((v_user->'permissions'->>'resetData')::boolean, false) is not true
  ) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์รีเซ็ตข้อมูล');
  end if;
  if p_scope is null or p_scope not in ('products', 'history', 'users', 'all') then
    return jsonb_build_object('ok', false, 'error', 'ขอบเขตการรีเซ็ตไม่ถูกต้อง');
  end if;

  if p_scope in ('products', 'all') then
    v_data := jsonb_set(v_data, '{products}', '[]'::jsonb);
  end if;
  if p_scope in ('history', 'all', 'users') then
    v_data := jsonb_set(v_data, '{log}', '[]'::jsonb);
  end if;
  if p_scope = 'users' then
    select coalesce(jsonb_agg(value), '[]'::jsonb) into v_user
    from jsonb_array_elements(v_data->'users') value
    where coalesce(value->>'role','')='admin' and coalesce((value->>'active')::boolean,false);
    v_data := jsonb_set(v_data, '{users}', v_user);
  end if;

  v_data := jsonb_set(v_data, '{lastReset}', jsonb_build_object(
    'scope', p_scope,
    'user', v_name,
    'ts', floor(extract(epoch from clock_timestamp()) * 1000)::bigint
  ), true);

  update private.inventory_state
  set data = v_data, version = version + 1, updated_at = now()
  where id=true and branch_id=v_branch_id
  returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_data), 'version', v_version);
end;
$$;

create or replace function public.api_storage_usage(p_token text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_name text; v_branch_id uuid; v_origin uuid; v_user jsonb; v_used bigint; v_quota bigint:=500::bigint*1024*1024;
begin
  select username,branch_id,manager_origin_branch_id into v_name,v_branch_id,v_origin from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name);
  if v_user is null then
    select value into v_user from private.inventory_state s cross join lateral jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) where s.id=true and s.branch_id=coalesce(v_origin,v_branch_id) and lower(value->>'name')=lower(v_name);
  end if;
  if v_origin is not null and v_user is not null then
     if coalesce((v_user->>'active')::boolean,false) is not true or (coalesce(v_user->>'role','')<>'admin' and coalesce((v_user->'permissions'->>'manageBranches')::boolean,false) is not true) then return jsonb_build_object('ok',false,'error','สิทธิ์จัดการสาขาถูกยกเลิก กรุณาเข้าสู่ระบบใหม่'); end if;
     v_user:=v_user||jsonb_build_object('role','admin');
   end if;
   if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true or (coalesce((v_user->>'owner')::boolean,false) is not true and coalesce(v_user->>'role','')<>'admin') then return jsonb_build_object('ok',false,'error','เฉพาะผู้ดูแลหลักหรือผู้ดูแลระบบเท่านั้นที่ดูข้อมูลนี้ได้'); end if;
  v_used:=pg_catalog.pg_database_size(pg_catalog.current_database());
  return jsonb_build_object('ok',true,'usedBytes',v_used,'quotaBytes',v_quota,'remainingBytes',greatest(v_quota-v_used,0),'usedPercent',round(v_used::numeric*100/v_quota,2),'checkedAt',now(),'quotaPlan','Free');
end $$;

revoke all on function public.api_branch_switch(text,uuid,text) from public,anon,authenticated;
grant execute on function public.api_branch_switch(text,uuid,text) to anon,authenticated;
notify pgrst,'reload schema';

commit;



-- เพิ่มกติกาความปลอดภัยสาขารุ่นล่าสุด
-- จำกัดการจัดการสาขาไว้ที่บัญชีหลัก kiangkai เท่านั้น
-- การปิดสาขาเป็นแบบพักใช้งาน เพื่อเก็บข้อมูลเดิมไว้และกู้คืนได้จากผู้ดูแลฐานข้อมูล
begin;

alter table private.inventory_sessions add column if not exists manager_origin_branch_id uuid;

-- ยุติเซสชันสลับสาขาที่ออกให้ผู้ใช้ทั่วไปจากระบบรุ่นก่อน
delete from private.inventory_sessions where manager_origin_branch_id is not null;

create or replace function public.api_branch_switch(p_token text,p_branch_id uuid,p_pin_hash text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_name text; v_branch_id uuid; v_user jsonb; v_data jsonb; v_version bigint; v_branch jsonb; v_fail private.inventory_login_failures%rowtype;
begin
  select username,branch_id into v_name,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now() for update;
  if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')='kiangkai' and lower(account->>'name')=lower(v_name);
  if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true then return jsonb_build_object('ok',false,'error','เฉพาะบัญชีหลัก kiangkai เท่านั้นที่สลับสาขาได้'); end if;
  select jsonb_build_object('id',id,'name',name) into v_branch from private.inventory_branches where id=p_branch_id and active;
  if v_branch is null then return jsonb_build_object('ok',false,'error','ไม่พบสาขาที่เลือก'); end if;
  insert into private.inventory_login_failures(branch_id,username) values(v_branch_id,lower(v_name)) on conflict(branch_id,username) do nothing;
  select * into v_fail from private.inventory_login_failures where branch_id=v_branch_id and username=lower(v_name) for update;
  if v_fail.blocked_until is not null and v_fail.blocked_until>now() then return jsonb_build_object('ok',false,'error','ลองยืนยันรหัสหลายครั้ง กรุณารอสักครู่'); end if;
  if coalesce(v_user->>'pin','')<>coalesce(p_pin_hash,'') then
    update private.inventory_login_failures set failures=case when failures>=4 then 0 else failures+1 end,blocked_until=case when failures>=4 then now()+interval '60 seconds' else null end where branch_id=v_branch_id and username=lower(v_name);
    return jsonb_build_object('ok',false,'error','รหัสผ่านไม่ถูกต้อง');
  end if;
  delete from private.inventory_login_failures where branch_id=v_branch_id and username=lower(v_name);
  select data,version into v_data,v_version from private.inventory_state where id=true and branch_id=p_branch_id;
  update private.inventory_sessions set branch_id=p_branch_id,manager_origin_branch_id=null,expires_at=now()+interval '7 days' where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex');
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'me',v_user-'pin','version',v_version,'branch',v_branch);
end $$;

create or replace function public.api_branch_create(p_token text,p_name text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_username text; v_branch_id uuid; v_user jsonb; v_name text:=trim(coalesce(p_name,'')); v_id uuid; v_roles jsonb;
begin
  select username,branch_id into v_username,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
  if v_username is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')='kiangkai' and lower(account->>'name')=lower(v_username);
  if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true then return jsonb_build_object('ok',false,'error','เฉพาะบัญชีหลัก kiangkai เท่านั้นที่เพิ่มสาขาได้'); end if;
  if length(v_name)<2 or length(v_name)>80 then return jsonb_build_object('ok',false,'error','ชื่อสาขาต้องยาว 2–80 ตัวอักษร'); end if;
  if exists(select 1 from private.inventory_branches where lower(name)=lower(v_name)) then return jsonb_build_object('ok',false,'error','มีชื่อสาขานี้แล้ว'); end if;
  v_id:=extensions.gen_random_uuid();
  select data->'roles' into v_roles from private.inventory_state where id=true and branch_id=v_branch_id;
  insert into private.inventory_branches(id,name,created_by) values(v_id,v_name,v_username);
  insert into private.inventory_state(id,branch_id,data,version) values(true,v_id,jsonb_build_object('users','[]'::jsonb,'products','[]'::jsonb,'log','[]'::jsonb,'roles',coalesce(v_roles,'{}'::jsonb),'categories','[]'::jsonb,'units','[]'::jsonb),1);
  return jsonb_build_object('ok',true,'branch',jsonb_build_object('id',v_id,'name',v_name));
end $$;

-- ปิดสาขาแบบเก็บข้อมูลไว้ ไม่ลบประวัติหรือสต็อกออกจากฐานข้อมูล
create or replace function public.api_branch_deactivate(p_token text,p_branch_id uuid)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_username text; v_current uuid; v_user jsonb; v_branch_name text; v_count integer;
begin
  select username,branch_id into v_username,v_current from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now() for update;
  if v_username is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select account into v_user from private.inventory_global_admin where id=true and lower(account->>'name')='kiangkai' and lower(account->>'name')=lower(v_username);
  if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true then return jsonb_build_object('ok',false,'error','เฉพาะบัญชีหลัก kiangkai เท่านั้นที่ปิดสาขาได้'); end if;
  if p_branch_id=v_current then return jsonb_build_object('ok',false,'error','กรุณาสลับไปสาขาอื่นก่อนปิดสาขานี้'); end if;
  select name into v_branch_name from private.inventory_branches where id=p_branch_id and active for update;
  if v_branch_name is null then return jsonb_build_object('ok',false,'error','ไม่พบสาขาที่เปิดใช้งาน'); end if;
  select count(*) into v_count from private.inventory_branches where active;
  if v_count<=1 then return jsonb_build_object('ok',false,'error','ต้องเหลือสาขาที่เปิดใช้งานอย่างน้อยหนึ่งสาขา'); end if;
  update private.inventory_branches set active=false where id=p_branch_id;
  delete from private.inventory_sessions where branch_id=p_branch_id;
  delete from private.inventory_login_failures where branch_id=p_branch_id;
  return jsonb_build_object('ok',true,'branch',jsonb_build_object('id',p_branch_id,'name',v_branch_name));
end $$;

revoke all on function public.api_branch_switch(text,uuid,text) from public,anon,authenticated;
revoke all on function public.api_branch_create(text,text) from public,anon,authenticated;
revoke all on function public.api_branch_deactivate(text,uuid) from public,anon,authenticated;
grant execute on function public.api_branch_switch(text,uuid,text) to anon,authenticated;
grant execute on function public.api_branch_create(text,text) to anon,authenticated;
grant execute on function public.api_branch_deactivate(text,uuid) to anon,authenticated;
notify pgrst,'reload schema';
commit;

-- ย้ายสิทธิผู้ดูแลหลักออกจากรายการบัญชีรายสาขา และปิดช่องทางปลอมสถานะ owner ผ่าน api_sync
begin;
update private.inventory_state s
set data=jsonb_set(s.data,'{users}',coalesce((select jsonb_agg(u.value - 'owner' order by u.ordinality) from jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) with ordinality u(value,ordinality)),'[]'::jsonb),true)
  ,version=version+1,updated_at=now()
where s.id=true and jsonb_typeof(s.data->'users')='array'
  and exists(select 1 from jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) u(value) where u.value ? 'owner');
create or replace function public.api_sync(p_token text, p_base jsonb, p_data jsonb)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
declare
  v_branch_id uuid; v_origin uuid;
  v_name text; v_data jsonb; v_user jsonb; v_version bigint; v_next jsonb; v_users jsonb;
  v_perm jsonb; v_log jsonb; v_add jsonb; v_products_changed boolean;
  v_users_changed boolean; v_lists_changed boolean;
begin
  select username,branch_id,manager_origin_branch_id into v_name,v_branch_id,v_origin from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  if v_origin is not null then return jsonb_build_object('ok',false,'error','เซสชันสลับสาขาถูกปิด กรุณาเข้าสู่ระบบใหม่'); end if;
  select data, version into v_data, v_version from private.inventory_state where id=true and branch_id=v_branch_id for update;
  if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then
     select account into v_user from private.inventory_global_admin where id=true;
   elsif v_origin is not null then
     select value into v_user from private.inventory_state src cross join lateral jsonb_array_elements(coalesce(src.data->'users','[]'::jsonb)) where src.id=true and src.branch_id=v_origin and lower(value->>'name')=lower(v_name);
     if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true or (coalesce(v_user->>'role','')<>'admin' and coalesce((v_user->'permissions'->>'manageBranches')::boolean,false) is not true) then return jsonb_build_object('ok',false,'error','สิทธิ์จัดการสาขาถูกยกเลิก กรุณาเข้าสู่ระบบใหม่'); end if;
     v_user:=v_user||jsonb_build_object('role','admin','permissions',jsonb_build_object('editStock',true,'manageLists',true,'manageUsers',true,'deleteUsers',true,'deleteStock',true,'managePermissions',true,'resetData',true,'manageBranches',true),'branchManagerAccess',true,'owner',true);
   else
     select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name);
   end if;
   if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;
  v_perm := coalesce(v_user->'permissions', '{}'::jsonb);
  v_products_changed := coalesce(p_base->'products', '[]'::jsonb) is distinct from coalesce(p_data->'products', '[]'::jsonb);
  v_users_changed := coalesce(p_base->'users', '[]'::jsonb) is distinct from coalesce(p_data->'users', '[]'::jsonb);
  if v_users_changed and exists(
    select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value)
    where coalesce((u.value->>'owner')::boolean,false)
  ) then
    return jsonb_build_object('ok',false,'error','ไม่อนุญาตให้บัญชีผู้ใช้ในสาขากำหนดสถานะผู้ดูแลหลัก');
  end if;
  v_lists_changed := coalesce(p_base->'roles', '{}'::jsonb) is distinct from coalesce(p_data->'roles', '{}'::jsonb)
    or coalesce(p_base->'categories', '[]'::jsonb) is distinct from coalesce(p_data->'categories', '[]'::jsonb)
    or coalesce(p_base->'units', '[]'::jsonb) is distinct from coalesce(p_data->'units', '[]'::jsonb);

  if v_users_changed and (
    exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) where lower(value->>'name')=lower((select account->>'name' from private.inventory_global_admin where id=true)))
    or exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) group by lower(value->>'name') having count(*)>1)
  ) then
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้ซ้ำหรือสงวนไว้สำหรับผู้ดูแลหลัก');
  end if;

  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_products_changed and not coalesce((v_perm->>'editStock')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการสต็อก');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'manageUsers')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการผู้ใช้');
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'deleteUsers')::boolean, false) and exists (
    select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) oldu
    where not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name')
  ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบผู้ใช้'); end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_users_changed and not coalesce((v_perm->>'managePermissions')::boolean, false) then
    if exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      join jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu on oldu->>'name'=newu->>'name'
      where coalesce(oldu->>'role','') is distinct from coalesce(newu->>'role','')
         or coalesce(oldu->'permissions','{}'::jsonb) is distinct from coalesce(newu->'permissions','{}'::jsonb)
    ) or exists (
      select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
      where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu where oldu->>'name'=newu->>'name')
        and (
          newu->>'role' in ('admin','supervisor')
          or coalesce(newu->'permissions','{}'::jsonb) is distinct from
            case newu->>'role'
              when 'admin' then '{"editStock":true,"manageLists":true,"manageUsers":true,"deleteUsers":true,"deleteStock":true,"managePermissions":true,"manageBranches":false}'::jsonb
              when 'supervisor' then '{"editStock":true,"manageLists":true,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false,"manageBranches":false}'::jsonb
              when 'staff' then '{"editStock":true,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false,"manageBranches":false}'::jsonb
              else '{"editStock":false,"manageLists":false,"manageUsers":false,"deleteUsers":false,"deleteStock":false,"managePermissions":false,"manageBranches":false}'::jsonb
            end
        )
    ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์กำหนดตำแหน่งหรือสิทธิ์'); end if;
  end if;
  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_lists_changed and not coalesce((v_perm->>'manageLists')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์แก้ไขรายการ');
  end if;

  -- ป้องกันการเขียนทับการแก้ไขของอีกเครื่องในหมวดเดียวกัน
  if v_products_changed and v_data->'products' is distinct from p_base->'products' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขสต็อกจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่แล้วทำรายการอีกครั้ง');
  end if;
  if v_users_changed and public.api_safe_state(v_data)->'users' is distinct from p_base->'users' then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขผู้ใช้จากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;
  if v_lists_changed and (v_data->'roles' is distinct from p_base->'roles' or v_data->'categories' is distinct from p_base->'categories' or v_data->'units' is distinct from p_base->'units') then
    return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขรายการจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
  end if;

  v_next := v_data;
  if v_products_changed then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'deleteStock')::boolean, false) then
      if exists(select 1 from jsonb_array_elements(v_data->'products') oldp where not exists (
        select 1 from jsonb_array_elements(coalesce(p_data->'products','[]'::jsonb)) newp where newp->>'id' = oldp->>'id'
      )) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบวัตถุดิบ'); end if;
    end if;
    v_next := jsonb_set(v_next, '{products}', coalesce(p_data->'products', '[]'::jsonb));
  end if;
  if v_users_changed then
    if exists(select 1 from jsonb_array_elements(v_data->'users') oldu where coalesce((oldu->>'owner')::boolean,false)
      and not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name' and newu->>'role'=oldu->>'role' and coalesce((newu->>'active')::boolean,false))) then
      return jsonb_build_object('ok', false, 'error', 'ไม่สามารถปิดหรือลบบัญชีผู้ดูแลหลักได้');
    end if;
    if not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u where u->>'role'='admin' and coalesce((u->>'active')::boolean,false)) and coalesce((v_user->>'owner')::boolean,false) is not true then
      return jsonb_build_object('ok', false, 'error', 'ต้องมีผู้ดูแลที่เปิดใช้งานอย่างน้อยหนึ่งบัญชี');
    end if;
    select coalesce(jsonb_agg(
      case when newu.user_data ? 'pin' then newu.user_data else newu.user_data || jsonb_build_object('pin', oldu.user_data->'pin') end order by newu.position
    ), '[]'::jsonb) into v_users
    from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) with ordinality as newu(user_data, position)
    left join jsonb_array_elements(v_data->'users') as oldu(user_data) on oldu.user_data->>'name'=newu.user_data->>'name';
    if exists(select 1 from jsonb_array_elements(v_users) as u(user_data) where coalesce(u.user_data->>'pin','') !~ '^[0-9a-f]{64}$') then
      return jsonb_build_object('ok', false, 'error', 'บัญชีผู้ใช้ต้องมีรหัส 6 หลักก่อนบันทึก');
    end if;
    v_next := jsonb_set(v_next, '{users}', v_users);
  end if;
  if v_lists_changed then
    v_next := jsonb_set(v_next, '{roles}', coalesce(p_data->'roles','{}'::jsonb));
    v_next := jsonb_set(v_next, '{categories}', coalesce(p_data->'categories','[]'::jsonb));
    v_next := jsonb_set(v_next, '{units}', coalesce(p_data->'units','[]'::jsonb));
  end if;

  -- ประวัติเป็นข้อมูลเพิ่มต่อท้าย ไม่ลบประวัติที่อุปกรณ์อื่นบันทึกไว้
  select coalesce(jsonb_agg(entry), '[]'::jsonb) into v_add
    from jsonb_array_elements(coalesce(p_data->'log','[]'::jsonb)) entry
    where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'log','[]'::jsonb)) oldentry where oldentry = entry);
  if jsonb_array_length(v_add) > 0 then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'editStock')::boolean, false) then
      return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์บันทึกประวัติสต็อก');
    end if;
    select coalesce(jsonb_agg((entry - 'user' - 'role') || jsonb_build_object('user', v_name, 'role', coalesce(v_data->'roles'->>(v_user->>'role'), v_user->>'role', 'พนักงานคลัง')) order by (entry->>'ts')::numeric desc), '[]'::jsonb)
      into v_log from jsonb_array_elements(v_add) entry;
    select coalesce(jsonb_agg(item order by ord), '[]'::jsonb) into v_log
      from (select item, ord from jsonb_array_elements(v_log || coalesce(v_data->'log','[]'::jsonb)) with ordinality as x(item,ord) order by ord limit 500) recent;
    v_next := jsonb_set(v_next, '{log}', v_log);
  end if;

  update private.inventory_state set data = v_next, version = version + 1, updated_at = now() where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_next), 'version', v_version);
end;
$$;

notify pgrst,'reload schema';
commit;



