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


