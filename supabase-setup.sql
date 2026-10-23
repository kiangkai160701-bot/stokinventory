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
    'theme', 'sakura',
    'units', jsonb_build_array('กิโลกรัม', 'กรัม', 'ลิตร', 'มิลลิลิตร', 'ชิ้น', 'แพ็ค', 'กล่อง', 'ขวด', 'ถุง')
  ),
  1
)
on conflict (id) do nothing;

create or replace function public.api_safe_state(p_data jsonb)
returns jsonb
language sql immutable
set search_path = ''
as $$
  select jsonb_set(
    p_data,
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

  if v_user->>'role' <> 'admin' and v_products_changed and not coalesce((v_perm->>'editStock')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการสต็อก');
  end if;
  if v_user->>'role' <> 'admin' and v_users_changed and not coalesce((v_perm->>'manageUsers')::boolean, false) then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการผู้ใช้');
  end if;
  if v_user->>'role' <> 'admin' and v_users_changed and not coalesce((v_perm->>'deleteUsers')::boolean, false) and exists (
    select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) oldu
    where not exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu where newu->>'name'=oldu->>'name')
  ) then return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์ลบผู้ใช้'); end if;
  if v_user->>'role' <> 'admin' and v_users_changed and not coalesce((v_perm->>'managePermissions')::boolean, false) then
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
  if v_user->>'role' <> 'admin' and v_lists_changed and not coalesce((v_perm->>'manageLists')::boolean, false) then
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
    if v_user->>'role' <> 'admin' and not coalesce((v_perm->>'deleteStock')::boolean, false) then
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
    if v_user->>'role' <> 'admin' and not coalesce((v_perm->>'editStock')::boolean, false) then
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
grant execute on function public.api_change_pin(text,text,text) to anon, authenticated;
grant execute on function public.api_update_owner_account(text,text,text,text) to anon, authenticated;
grant execute on function public.api_update_username(text,text,text) to anon, authenticated;
grant execute on function public.api_logout(text) to anon, authenticated;
grant execute on function public.api_presence_tick(text) to anon, authenticated;

notify pgrst, 'reload schema';
