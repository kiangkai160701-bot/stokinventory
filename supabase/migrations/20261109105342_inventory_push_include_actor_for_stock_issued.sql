-- Add the authenticated actor name to stock-issue push notifications only.
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
  -- จ๊อบพนักงาน: ส่งมาเฉพาะเมื่อมีฟิลด์ jobs และต่างจากฐานข้อมูลเดิม
  v_jobs_changed := (p_data ? 'jobs') and jsonb_typeof(p_data->'jobs') = 'object'
    and (p_data->'jobs') is distinct from coalesce(p_base->'jobs', 'null'::jsonb);
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
    v_next := jsonb_set(v_next, '{jobs}', p_data->'jobs', true);
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
    -- เก็บประวัติย้อนหลัง 6 เดือน ไม่จำกัดจำนวนรายการ ส่วนที่เก่ากว่านั้นย้ายเข้าตารางถาวร ไม่ลบทิ้ง
    select coalesce(jsonb_agg(item order by ord), '[]'::jsonb) into v_log
      from jsonb_array_elements(v_all) with ordinality as x(item,ord) where not coalesce(case when (item->>'ts') ~ '^[0-9]+(\.[0-9]+)?$' then (item->>'ts')::numeric < v_cutoff end, false);
    insert into private.inventory_log_archive(branch_id, ts, pid, entry)
      select v_branch_id, (item->>'ts')::numeric::bigint, coalesce(item->>'pid',''), item
        from jsonb_array_elements(v_all) with ordinality as x(item,ord)
        where coalesce(case when (item->>'ts') ~ '^[0-9]+(\.[0-9]+)?$' then (item->>'ts')::numeric < v_cutoff end, false)
      on conflict do nothing;
    v_next := jsonb_set(v_next, '{log}', v_log);
  end if;


  -- Queue push events inside the same transaction as the stock state update.
  insert into public.inventory_push_events(event_id, branch_id, event_type, payload)
  select md5(v_branch_id::text || ':' || coalesce(entry->>'ts','') || ':' || coalesce(entry->>'pid','') || ':' || coalesce(entry->>'type','')),
         v_branch_id,
         case entry->>'type'
           when 'in' then 'stock_received'
           when 'out' then 'stock_issued'
           when 'adjust' then 'stock_adjusted'
           when 'create' then 'product_created'
           when 'edit' then 'product_updated'
           when 'delete' then 'product_deleted'
           when 'transfer' then 'stock_transferred'
           when 'stock_transfer' then 'stock_transferred'
           when 'return' then 'stock_returned'
           when 'stock_return' then 'stock_returned'
           else null
         end,
         jsonb_build_object(
           'title', case entry->>'type'
             when 'in' then 'รับสินค้าเข้าคลัง'
             when 'out' then 'เบิกสินค้าออก'
             when 'adjust' then 'ปรับยอดสต๊อก'
             when 'create' then 'เพิ่มสินค้าใหม่'
             when 'edit' then 'แก้ไขข้อมูลสินค้า'
             when 'delete' then 'ลบสินค้า'
             when 'transfer' then 'โอนย้ายสินค้าระหว่างสาขา'
             when 'stock_transfer' then 'โอนย้ายสินค้าระหว่างสาขา'
             when 'return' then 'คืนสินค้าเข้าคลัง'
             when 'stock_return' then 'คืนสินค้าเข้าคลัง'
           end,
           'body', left(coalesce(entry->>'pname','รายการสินค้า') || case when entry ? 'amt' then ' · ' || coalesce(entry->>'amt','') || ' ' || coalesce(entry->>'unit','') else '' end || case when entry->>'type'='out' then ' · ผู้ทำรายการ: ' || v_name else '' end, 240),
           'url', '/'
         )
    from jsonb_array_elements(coalesce(v_add,'[]'::jsonb)) entry
   where case entry->>'type'
     when 'in' then true when 'out' then true when 'adjust' then true
     when 'create' then true when 'edit' then true when 'delete' then true
     when 'transfer' then true when 'stock_transfer' then true
     when 'return' then true when 'stock_return' then true
     else false end
  on conflict(event_id) do nothing;

  -- Notify only when a product crosses its configured low-stock or zero threshold.
  insert into public.inventory_push_events(event_id, branch_id, event_type, payload)
  select md5(v_branch_id::text || ':threshold:' || coalesce(newp->>'id','') || ':' ||
            case when coalesce((newp->>'qty')::numeric,0) <= 0 then 'out_of_stock' else 'low_stock' end ||
            ':' || coalesce((select version::text from private.inventory_state where id=true and branch_id=v_branch_id),'0')),
         v_branch_id,
         case when coalesce((newp->>'qty')::numeric,0) <= 0 then 'out_of_stock' else 'low_stock' end,
         jsonb_build_object(
           'title', case when coalesce((newp->>'qty')::numeric,0) <= 0 then 'สินค้าหมดสต๊อก' else 'สินค้าใกล้หมด' end,
           'body', left(coalesce(newp->>'name','สินค้า') || ' · คงเหลือ ' || coalesce(newp->>'qty','0') || ' ' || coalesce(newp->>'unit',''),180),
           'url','/'
         )
    from jsonb_array_elements(coalesce(v_next->'products','[]'::jsonb)) newp
   where exists (
     select 1 from jsonb_array_elements(coalesce(v_data->'products','[]'::jsonb)) oldp
      where oldp->>'id'=newp->>'id'
        and coalesce((oldp->>'qty')::numeric,0) > 0
        and (
          (coalesce((newp->>'qty')::numeric,0) <= 0)
          or (
            coalesce((newp->>'min')::numeric,0) > 0
            and coalesce((oldp->>'qty')::numeric,0) > coalesce((oldp->>'min')::numeric,0)
            and coalesce((newp->>'qty')::numeric,0) <= coalesce((newp->>'min')::numeric,0)
            and coalesce((newp->>'qty')::numeric,0) > 0
          )
        )
   )
  on conflict(event_id) do nothing;

  -- Notify when a new user account is added to this branch.
  insert into public.inventory_push_events(event_id, branch_id, event_type, payload)
  select md5(v_branch_id::text || ':user_created:' || lower(newu->>'name')),
         v_branch_id, 'user_created',
         jsonb_build_object('title','มีผู้ใช้งานใหม่','body','เพิ่มบัญชี ' || left(coalesce(newu->>'name','ผู้ใช้'),80),'url','/')
    from jsonb_array_elements(coalesce(v_users,'[]'::jsonb)) newu
   where v_users_changed
     and not exists(select 1 from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb)) oldu where lower(oldu->>'name')=lower(newu->>'name'))
  on conflict(event_id) do nothing;

  update private.inventory_state set data = v_next, version = version + 1, updated_at = now() where id=true and branch_id=v_branch_id returning version into v_version;
  return jsonb_build_object('ok', true, 'state', public.api_safe_state(v_next), 'version', v_version);
end;
$function$

