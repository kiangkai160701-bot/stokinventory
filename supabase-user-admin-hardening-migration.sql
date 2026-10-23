-- ลบบัญชี boykiangkai จากทุกสาขา ยกเลิกเซสชัน และจำกัดการสร้างตำแหน่งผู้ดูแลระบบ
-- เก็บประวัติการทำรายการเดิมไว้เพื่อการตรวจสอบย้อนหลัง
begin;

update private.inventory_state s
set data=jsonb_set(s.data,'{users}',coalesce((select jsonb_agg(u.value order by u.ordinality) from jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) with ordinality u(value,ordinality) where lower(trim(u.value->>'name')) <> 'boykiangkai'),'[]'::jsonb),true),
    version=s.version+1,updated_at=now()
where s.id=true and jsonb_typeof(s.data->'users')='array'
  and exists(select 1 from jsonb_array_elements(coalesce(s.data->'users','[]'::jsonb)) u(value) where lower(trim(u.value->>'name'))='boykiangkai');

delete from private.inventory_sessions where lower(username)='boykiangkai';
delete from private.inventory_login_failures where lower(username)='boykiangkai';
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

create or replace function public.api_update_owner_account(p_token text,p_old_hash text,p_new_name text,p_new_hash text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_old text; v_branch_id uuid; v_name text:=lower(trim(coalesce(p_new_name,''))); v_user jsonb; v_data jsonb; v_version bigint;
begin
  if v_name='boykiangkai' then return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้นี้ถูกสงวนไว้'); end if;
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
  if v_name='boykiangkai' then return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้นี้ถูกสงวนไว้'); end if;
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

notify pgrst,'reload schema';
commit;


