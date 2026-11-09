-- Stock Inventory Web Push infrastructure.
-- VAPID and dispatcher secrets are stored in Supabase Vault and are intentionally not committed here.
create extension if not exists pg_net;
create table if not exists public.inventory_push_subscriptions (
 id uuid primary key default gen_random_uuid(), username text not null, branch_id uuid not null,
 device_id text not null, endpoint text not null unique, p256dh text not null, auth text not null,
 user_agent text, preferences jsonb not null default '{"low_stock":true,"out_of_stock":true}'::jsonb,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 last_seen_at timestamptz not null default now(),
 constraint inventory_push_device_unique unique(username,branch_id,device_id),
 constraint inventory_push_preferences_object check(jsonb_typeof(preferences)='object')
);
create table if not exists public.inventory_push_events (
 event_id text primary key, branch_id uuid not null, event_type text not null,
 payload jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(),
 processed_at timestamptz, claimed_at timestamptz
);
alter table public.inventory_push_events add column if not exists payload jsonb not null default '{}'::jsonb;
alter table public.inventory_push_events add column if not exists processed_at timestamptz;
alter table public.inventory_push_events add column if not exists claimed_at timestamptz;
create table if not exists public.inventory_push_deliveries (
 event_id text not null references public.inventory_push_events(event_id) on delete cascade,
 subscription_id uuid not null references public.inventory_push_subscriptions(id) on delete cascade,
 delivered_at timestamptz not null default now(), primary key(event_id,subscription_id)
);
create index if not exists inventory_push_subscriptions_branch_idx on public.inventory_push_subscriptions(branch_id);
create index if not exists inventory_push_subscriptions_user_idx on public.inventory_push_subscriptions(username,branch_id);
create index if not exists inventory_push_events_pending_idx on public.inventory_push_events(branch_id,created_at) where processed_at is null;
alter table public.inventory_push_subscriptions enable row level security;
alter table public.inventory_push_events enable row level security;
alter table public.inventory_push_deliveries enable row level security;
revoke all on public.inventory_push_subscriptions from public,anon,authenticated;
revoke all on public.inventory_push_events from public,anon,authenticated;
revoke all on public.inventory_push_deliveries from public,anon,authenticated;
grant all on public.inventory_push_subscriptions to service_role;
grant all on public.inventory_push_events to service_role;
grant all on public.inventory_push_deliveries to service_role;
CREATE OR REPLACE FUNCTION public.notification_auth_context(p_token text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_session record;
begin
  select username, branch_id, manager_origin_branch_id
    into v_session
    from private.inventory_sessions
   where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
     and expires_at > now();
  if v_session.username is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  return jsonb_build_object(
    'ok', true,
    'username', v_session.username,
    'branch_id', v_session.branch_id,
    'manager_origin_branch_id', v_session.manager_origin_branch_id
  );
end;
$function$

CREATE OR REPLACE FUNCTION public.notification_register_device(p_token text, p_device_id text, p_endpoint text, p_p256dh text, p_auth text, p_user_agent text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_ctx jsonb; v_id uuid;
begin
  v_ctx := public.notification_auth_context(p_token);
  if coalesce((v_ctx->>'ok')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  if coalesce(length(p_device_id),0) < 8 or length(p_device_id) > 120
     or coalesce(p_endpoint,'') !~ '^https://'
     or length(p_endpoint) > 3000
     or coalesce(length(p_p256dh),0) < 20 or length(p_p256dh) > 256
     or coalesce(length(p_auth),0) < 8 or length(p_auth) > 256 then
    return jsonb_build_object('ok', false, 'error', 'invalid_subscription');
  end if;
  -- A browser push endpoint can belong to only one active account/branch at a time.
  delete from public.inventory_push_subscriptions
   where endpoint = p_endpoint
     and username = v_ctx->>'username'
     and (branch_id <> (v_ctx->>'branch_id')::uuid or device_id <> p_device_id);

  insert into public.inventory_push_subscriptions
    (username, branch_id, device_id, endpoint, p256dh, auth, user_agent, last_seen_at, updated_at)
  values
    (v_ctx->>'username', (v_ctx->>'branch_id')::uuid, p_device_id, p_endpoint, p_p256dh, p_auth, left(coalesce(p_user_agent,''),500), now(), now())
  on conflict (username, branch_id, device_id) do update set
    endpoint = excluded.endpoint,
    p256dh = excluded.p256dh,
    auth = excluded.auth,
    user_agent = excluded.user_agent,
    last_seen_at = now(),
    updated_at = now()
  returning id into v_id;
  return jsonb_build_object('ok', true, 'subscription_id', v_id);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'error', 'subscription_in_use');
end;
$function$

CREATE OR REPLACE FUNCTION public.notification_update_preferences(p_token text, p_device_id text, p_preferences jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_ctx jsonb; v_updated integer;
begin
  v_ctx := public.notification_auth_context(p_token);
  if coalesce((v_ctx->>'ok')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  if jsonb_typeof(p_preferences) <> 'object' then
    return jsonb_build_object('ok', false, 'error', 'invalid_preferences');
  end if;
  if exists (
    select 1 from jsonb_each(p_preferences) e
    where e.key not in ('low_stock','out_of_stock','stock_received','stock_issued','stock_transferred','stock_returned','product_created','product_updated','product_deleted','stock_adjusted','request_created','request_approved','request_rejected','branch_changed','user_created')
       or jsonb_typeof(e.value) <> 'boolean'
  ) then
    return jsonb_build_object('ok', false, 'error', 'invalid_preferences');
  end if;
  update public.inventory_push_subscriptions
     set preferences = coalesce(preferences, '{}'::jsonb) || p_preferences,
         updated_at = now(),
         last_seen_at = now()
   where username = v_ctx->>'username'
     and branch_id = (v_ctx->>'branch_id')::uuid
     and device_id = p_device_id;
  get diagnostics v_updated = row_count;
  return jsonb_build_object('ok', v_updated = 1, 'updated', v_updated);
end;
$function$

CREATE OR REPLACE FUNCTION public.notification_remove_device(p_token text, p_device_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_ctx jsonb; v_deleted integer;
begin
  v_ctx := public.notification_auth_context(p_token);
  if coalesce((v_ctx->>'ok')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  delete from public.inventory_push_subscriptions
   where username = v_ctx->>'username'
     and branch_id = (v_ctx->>'branch_id')::uuid
     and device_id = p_device_id;
  get diagnostics v_deleted = row_count;
  return jsonb_build_object('ok', true, 'deleted', v_deleted);
end;
$function$

CREATE OR REPLACE FUNCTION public.claim_inventory_push_events(p_limit integer DEFAULT 40, p_branch_id uuid DEFAULT NULL::uuid)
 RETURNS SETOF inventory_push_events
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with picked as (
    select e.event_id
      from public.inventory_push_events e
     where e.processed_at is null
       and (p_branch_id is null or e.branch_id = p_branch_id)
       and (e.claimed_at is null or e.claimed_at < now() - interval '5 minutes')
     order by e.created_at
     for update skip locked
     limit greatest(1, least(coalesce(p_limit, 40), 100))
  )
  update public.inventory_push_events e
     set claimed_at = now()
    from picked
   where e.event_id = picked.event_id
  returning e.*;
$function$

CREATE OR REPLACE FUNCTION public.get_inventory_push_config()
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select jsonb_build_object(
    'vapid_public_key', (select decrypted_secret from vault.decrypted_secrets where name='inventory_push_vapid_public_key' limit 1),
    'vapid_private_key', (select decrypted_secret from vault.decrypted_secrets where name='inventory_push_vapid_private_key' limit 1),
    'vapid_subject', (select decrypted_secret from vault.decrypted_secrets where name='inventory_push_vapid_subject' limit 1),
    'cron_secret', (select decrypted_secret from vault.decrypted_secrets where name='inventory_push_cron_secret' limit 1)
  );
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
           'body', left(coalesce(entry->>'pname','รายการสินค้า') || case when entry ? 'amt' then ' · ' || coalesce(entry->>'amt','') || ' ' || coalesce(entry->>'unit','') else '' end, 180),
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

CREATE OR REPLACE FUNCTION public.api_branch_create(p_token text, p_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
  insert into public.inventory_push_events(event_id,branch_id,event_type,payload)
  select md5(v_id::text || ':branch_created:' || b.id::text), b.id, 'branch_changed',
         jsonb_build_object('title','เพิ่มสาขาใหม่','body','เพิ่มสาขา ' || left(v_name,80),'url','/')
    from private.inventory_branches b where b.active and b.id = v_branch_id
  on conflict(event_id) do nothing;
  return jsonb_build_object('ok',true,'branch',jsonb_build_object('id',v_id,'name',v_name));
end $function$

CREATE OR REPLACE FUNCTION public.api_branch_deactivate(p_token text, p_branch_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
  insert into public.inventory_push_events(event_id,branch_id,event_type,payload)
  select md5(p_branch_id::text || ':branch_deactivated:' || b.id::text), b.id, 'branch_changed',
         jsonb_build_object('title','ปิดการใช้งานสาขา','body','ปิดสาขา ' || left(v_branch_name,80),'url','/')
    from private.inventory_branches b where b.active and b.id = v_current
  on conflict(event_id) do nothing;
  return jsonb_build_object('ok',true,'branch',jsonb_build_object('id',p_branch_id,'name',v_branch_name));
end $function$

-- Required Vault names: inventory_push_vapid_public_key, inventory_push_vapid_private_key,
-- inventory_push_vapid_subject, inventory_push_cron_secret. Never commit secret values.
select cron.unschedule(jobid) from cron.job where jobname='inventory-push-dispatch';
select cron.schedule('inventory-push-dispatch','* * * * *',$job$
 select net.http_post(
  url := 'https://pxklhstbxmhykeqlmyfr.supabase.co/functions/v1/push-dispatch',
  body := '{"action":"dispatch"}'::jsonb,
  headers := jsonb_build_object('Content-Type','application/json','x-push-cron-secret',
    (select decrypted_secret from vault.decrypted_secrets where name='inventory_push_cron_secret' limit 1)),
  timeout_milliseconds := 55000
 );
$job$);
