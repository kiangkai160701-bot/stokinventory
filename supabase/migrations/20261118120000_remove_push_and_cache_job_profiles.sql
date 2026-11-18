-- Remove Web Push and keep job profile images out of routine inventory payloads.
CREATE OR REPLACE FUNCTION public.api_safe_state(p_data jsonb)
 RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO ''
AS $function$
  select jsonb_set(jsonb_set(p_data - 'theme','{users}',
    coalesce((select jsonb_agg(x.user_data - 'pin' order by x.position)
      from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) with ordinality as x(user_data,position)),'[]'::jsonb)),
    '{jobs}',case when jsonb_typeof(p_data->'jobs')='object' then (p_data->'jobs')-'profiles' else coalesce(p_data->'jobs','{}'::jsonb) end,true);
$function$
CREATE OR REPLACE FUNCTION public.api_get_state_version(p_token text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_branch_id uuid;
  v_name text;
  v_data jsonb;
  v_user jsonb;
  v_version bigint;
  v_origin uuid;
begin
  select username, branch_id, manager_origin_branch_id
    into v_name, v_branch_id, v_origin
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();

  if v_name is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select data, version into v_data, v_version
  from private.inventory_state
  where id = true and branch_id = v_branch_id;

  if exists (
    select 1 from private.inventory_global_admin
    where id = true and lower(account->>'name') = lower(v_name)
  ) then
    select account into v_user from private.inventory_global_admin where id = true;
  elsif v_origin is not null then
    select value into v_user
    from private.inventory_state src
    cross join lateral jsonb_array_elements(coalesce(src.data->'users', '[]'::jsonb))
    where src.id = true and src.branch_id = v_origin
      and lower(value->>'name') = lower(v_name);

    if v_user is null
       or coalesce((v_user->>'active')::boolean, false) is not true
       or (coalesce(v_user->>'role', '') <> 'admin'
           and coalesce((v_user->'permissions'->>'manageBranches')::boolean, false) is not true) then
      return jsonb_build_object('ok', false, 'error', 'สิทธิ์จัดการสาขาถูกยกเลิก กรุณาเข้าสู่ระบบใหม่');
    end if;
  else
    select value into v_user
    from jsonb_array_elements(coalesce(v_data->'users', '[]'::jsonb))
    where lower(value->>'name') = lower(v_name);
  end if;

  if v_user is null or coalesce((v_user->>'active')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ถูกปิดใช้งาน');
  end if;

  return jsonb_build_object(
    'ok', true,
    'version', v_version,
    'profilesVersion', md5(coalesce(v_data->'jobs'->'profiles','{}'::jsonb)::text),
    'branch', (select jsonb_build_object('id', id, 'name', name)
               from private.inventory_branches where id = v_branch_id)
  );
end;
$function$

CREATE OR REPLACE FUNCTION public.api_sync(p_token text, p_base jsonb, p_data jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_branch_id uuid; v_origin uuid;
  v_name text; v_data jsonb; v_user jsonb; v_version bigint; v_next jsonb; v_users jsonb;
  v_perm jsonb; v_log jsonb; v_add jsonb; v_all jsonb; v_products_changed boolean;
  v_users_changed boolean; v_lists_changed boolean; v_jobs_changed boolean;
  v_cutoff numeric;
BEGIN
  IF NOT private.inventory_after_hours_write_allowed(p_token) THEN
    RETURN jsonb_build_object('ok', false, 'readonly', true, 'error', 'ขณะนี้เว็บไซต์อยู่ในช่วงปิดทำการ (22:00–06:00 น.) เพื่อประหยัดปริมาณรับส่งข้อมูล อนุญาตให้ดูข้อมูลเท่านั้น');
  END IF;

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
  -- จ๊อบพนักงาน: ส่งมาเฉพาะเมื่อมีฟิลด์ jobs และต่างจากฐานข้อมูลเดิม
  v_jobs_changed := (p_data ? 'jobs') and jsonb_typeof(p_data->'jobs') = 'object'
    and ((p_data->'jobs' - 'profiles') is distinct from (coalesce(p_base->'jobs','{}'::jsonb) - 'profiles'));
  if v_jobs_changed then
    if length((p_data->'jobs')::text) > 1000000 then
      return jsonb_build_object('ok', false, 'error', 'ข้อมูลจ๊อบพนักงานมีขนาดใหญ่เกินไป');
    end if;
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai'
       and coalesce((v_user->>'owner')::boolean, false) is not true
       and not coalesce((v_perm->>'manageJobs')::boolean, v_user->>'role' = 'supervisor', false) then
      return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์จัดการจ๊อบพนักงาน');
    end if;
    if coalesce(v_data->'jobs', 'null'::jsonb) is distinct from coalesce(p_base->'jobs', 'null'::jsonb) then
      return jsonb_build_object('ok', false, 'conflict', true, 'error', 'มีการแก้ไขจ๊อบพนักงานจากอีกเครื่อง กรุณาโหลดหน้าเว็บใหม่');
    end if;
  end if;

  if v_users_changed and (
    exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) where lower(value->>'name')=lower((select account->>'name' from private.inventory_global_admin where id=true)))
    or exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) where lower(trim(value->>'name'))='boykiangkai')
    or exists(select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) u(value) group by lower(value->>'name') having count(*)>1)
  ) then
    return jsonb_build_object('ok', false, 'error', 'ชื่อผู้ใช้ซ้ำหรือสงวนไว้สำหรับผู้ดูแลหลัก');
  end if;

  if v_users_changed and coalesce(v_user->>'role','') <> 'admin' and exists(
    select 1 from jsonb_array_elements(coalesce(p_data->'users','[]'::jsonb)) newu
    where lower(coalesce(newu->>'role',''))='admin'
      and not exists(select 1 from jsonb_array_elements(coalesce(p_base->'users','[]'::jsonb)) oldu where lower(oldu->>'name')=lower(newu->>'name') and lower(coalesce(oldu->>'role',''))='admin')
  ) then
    return jsonb_build_object('ok',false,'error','เฉพาะผู้ดูแลระบบเท่านั้นที่เพิ่มหรือเลื่อนบัญชีเป็นผู้ดูแลระบบได้');
  end if;  if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and v_products_changed and not coalesce((v_perm->>'editStock')::boolean, false) then
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

  if v_jobs_changed then
    v_next := jsonb_set(v_next, '{jobs}', coalesce(p_data->'jobs','{}'::jsonb) || jsonb_build_object('profiles',coalesce(v_data->'jobs'->'profiles','{}'::jsonb)),true);
  end if;

  -- ประวัติเป็นข้อมูลเพิ่มต่อท้าย ไม่ลบประวัติที่อุปกรณ์อื่นบันทึกไว้
  -- กันซ้ำ: ข้ามรายการที่มีอยู่ในฐานข้อมูลแล้ว (เทียบ ts + pid) จะได้ไม่ถูกประทับชื่อผู้ใช้ทับและไม่เกิดรายการซ้ำ
  select coalesce(jsonb_agg(d.entry), '[]'::jsonb) into v_add
    from (
      select distinct on (coalesce(entry->>'ts', entry::text), coalesce(entry->>'pid',''), coalesce(entry->>'type','')) entry
        from jsonb_array_elements(coalesce(p_data->'log','[]'::jsonb)) entry
        where not exists(select 1 from jsonb_array_elements(coalesce(p_base->'log','[]'::jsonb)) oldentry where oldentry = entry)
          and not exists(select 1 from jsonb_array_elements(coalesce(v_data->'log','[]'::jsonb)) cur
                          where cur->>'ts' = entry->>'ts' and coalesce(cur->>'pid','') = coalesce(entry->>'pid',''))
        order by coalesce(entry->>'ts', entry::text), coalesce(entry->>'pid',''), coalesce(entry->>'type','')
    ) d;
  if jsonb_array_length(v_add) > 0 then
    if v_user->>'role' <> 'admin' and lower(v_name) <> 'kiangkai' and coalesce((v_user->>'owner')::boolean,false) is not true and not coalesce((v_perm->>'editStock')::boolean, false) then
      return jsonb_build_object('ok', false, 'error', 'บัญชีนี้ไม่มีสิทธิ์บันทึกประวัติสต็อก');
    end if;
    select coalesce(jsonb_agg((entry - 'user' - 'role') || jsonb_build_object('user', v_name, 'role', coalesce(v_data->'roles'->>(v_user->>'role'), v_user->>'role', 'พนักงานคลัง')) order by (entry->>'ts')::numeric desc), '[]'::jsonb)
      into v_log from jsonb_array_elements(v_add) entry;
    v_all := v_log || coalesce(v_data->'log','[]'::jsonb);
    v_cutoff := extract(epoch from (now() - interval '6 months')) * 1000;

    -- เก็บเฉพาะประวัติในช่วง 6 เดือนล่าสุด และไม่ย้ายรายการเก่าไปคลัง
    select coalesce(jsonb_agg(item order by ord), '[]'::jsonb) into v_log
      from jsonb_array_elements(v_all) with ordinality as x(item,ord)
      where not coalesce(case when (item->>'ts') ~ '^[0-9]+([.][0-9]+)?$' then (item->>'ts')::numeric < v_cutoff end, false);
    v_next := jsonb_set(v_next, '{log}', v_log);

    v_next := jsonb_set(v_next, '{log}', v_log);
  end if;


  update private.inventory_state set data = v_next, version = version + 1, updated_at = now() where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_next), 'version', v_version);
end;
$function$

CREATE OR REPLACE FUNCTION public.api_branch_create(p_token text, p_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_username text; v_branch_id uuid; v_user jsonb; v_name text:=trim(coalesce(p_name,'')); v_id uuid; v_roles jsonb;
BEGIN
  IF NOT private.inventory_after_hours_write_allowed(p_token) THEN
    RETURN jsonb_build_object('ok', false, 'readonly', true, 'error', 'ขณะนี้เว็บไซต์อยู่ในช่วงปิดทำการ (22:00–06:00 น.) เพื่อประหยัดปริมาณรับส่งข้อมูล อนุญาตให้ดูข้อมูลเท่านั้น');
  END IF;

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
end $function$

CREATE OR REPLACE FUNCTION public.api_branch_deactivate(p_token text, p_branch_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_username text; v_current uuid; v_user jsonb; v_branch_name text; v_count integer;
BEGIN
  IF NOT private.inventory_after_hours_write_allowed(p_token) THEN
    RETURN jsonb_build_object('ok', false, 'readonly', true, 'error', 'ขณะนี้เว็บไซต์อยู่ในช่วงปิดทำการ (22:00–06:00 น.) เพื่อประหยัดปริมาณรับส่งข้อมูล อนุญาตให้ดูข้อมูลเท่านั้น');
  END IF;

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
end $function$


CREATE OR REPLACE FUNCTION public.api_job_profiles_get(p_token text)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $function$
declare v_branch_id uuid; v_data jsonb; v_name text;
begin
 select username,branch_id into v_name,v_branch_id from private.inventory_sessions
 where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
 if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
 select data into v_data from private.inventory_state where id=true and branch_id=v_branch_id;
 return jsonb_build_object('ok',true,'profiles',coalesce(v_data->'jobs'->'profiles','{}'::jsonb),
 'profilesVersion',md5(coalesce(v_data->'jobs'->'profiles','{}'::jsonb)::text));
end;$function$;

CREATE OR REPLACE FUNCTION public.api_job_profile_set(p_token text,p_name text,p_data text)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO ''
AS $function$
declare v_branch_id uuid; v_name text; v_user jsonb; v_data jsonb; v_profiles jsonb;
begin
 if not private.inventory_after_hours_write_allowed(p_token) then return jsonb_build_object('ok',false,'readonly',true,'error','ขณะนี้เว็บไซต์อยู่ในช่วงปิดทำการ (22:00–06:00 น.)'); end if;
 if coalesce(length(trim(p_name)),0)<1 or length(p_name)>100 then return jsonb_build_object('ok',false,'error','ชื่อพนักงานไม่ถูกต้อง'); end if;
 if p_data is not null and (length(p_data)>300000 or p_data !~ '^data:image/webp;base64,[A-Za-z0-9+/=]+$') then return jsonb_build_object('ok',false,'error','รูปโปรไฟล์ไม่ถูกต้องหรือมีขนาดใหญ่เกินไป'); end if;
 select username,branch_id into v_name,v_branch_id from private.inventory_sessions where token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at>now();
 if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
 select data into v_data from private.inventory_state where id=true and branch_id=v_branch_id for update;
 if exists(select 1 from private.inventory_global_admin where id=true and lower(account->>'name')=lower(v_name)) then select account into v_user from private.inventory_global_admin where id=true;
 else select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) where lower(value->>'name')=lower(v_name); end if;
 if v_user is null or coalesce((v_user->>'active')::boolean,false) is not true then return jsonb_build_object('ok',false,'error','บัญชีนี้ไม่มีสิทธิ์จัดการรูปโปรไฟล์'); end if;
 if lower(v_name)<>'kiangkai' and v_user->>'role'<>'supervisor' and not coalesce((v_user->'permissions'->>'manageJobs')::boolean,false) then return jsonb_build_object('ok',false,'error','เฉพาะหัวหน้างานเท่านั้นที่จัดการรูปโปรไฟล์ได้'); end if;
 v_profiles:=coalesce(v_data->'jobs'->'profiles','{}'::jsonb);
 if p_data is null then v_profiles:=v_profiles-p_name; else v_profiles:=jsonb_set(v_profiles,array[p_name],to_jsonb(p_data),true); end if;
 update private.inventory_state set data=jsonb_set(coalesce(data,'{}'::jsonb),'{jobs}',coalesce(data->'jobs','{}'::jsonb)||jsonb_build_object('profiles',v_profiles),true),version=version+1,updated_at=now() where id=true and branch_id=v_branch_id;
 return jsonb_build_object('ok',true,'profilesVersion',md5(v_profiles::text));
end;$function$;
GRANT EXECUTE ON FUNCTION public.api_job_profiles_get(text) TO anon,authenticated;
GRANT EXECUTE ON FUNCTION public.api_job_profile_set(text,text,text) TO anon,authenticated;


select cron.unschedule(jobid) from cron.job where jobname in ('inventory-push-dispatch','inventory-push-retention-3-days');
delete from public.inventory_push_subscriptions;
delete from public.inventory_push_events;
drop function if exists public.notification_register_device(text,text,text,text,text,text);
drop function if exists public.notification_update_preferences(text,text,jsonb);
drop function if exists public.notification_remove_device(text,text);
drop function if exists public.notification_auth_context(text);
drop function if exists public.claim_inventory_push_events(integer,uuid);
drop function if exists public.get_inventory_push_config();
drop table if exists public.inventory_push_deliveries cascade;
drop table if exists public.inventory_push_subscriptions cascade;
drop table if exists public.inventory_push_events cascade;

