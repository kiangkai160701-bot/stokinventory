-- Keep ordinary accounts active in only one branch at a time.
-- The global administrator (kiangkai) is intentionally exempt.
create or replace function public.api_branch_login(p_branch_id uuid, p_name text, p_pin_hash text)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_name text := lower(trim(coalesce(p_name,'')));
  v_data jsonb;
  v_user jsonb;
  v_fail private.inventory_login_failures%rowtype;
  v_token text;
  v_version bigint;
  v_branch jsonb;
  v_is_global_admin boolean := false;
begin
  if v_name='' or coalesce(p_pin_hash,'') !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('ok',false,'error','ข้อมูลเข้าสู่ระบบไม่ถูกต้อง');
  end if;

  select jsonb_build_object('id',id,'name',name) into v_branch
    from private.inventory_branches where id=p_branch_id and active;
  if v_branch is null then
    return jsonb_build_object('ok',false,'error','ไม่พบสาขาที่เลือก');
  end if;

  insert into private.inventory_login_failures(branch_id,username)
  values(p_branch_id,v_name) on conflict(branch_id,username) do nothing;
  select * into v_fail from private.inventory_login_failures
   where branch_id=p_branch_id and username=v_name for update;
  if v_fail.blocked_until is not null and v_fail.blocked_until>now() then
    return jsonb_build_object('ok',false,'error','ลองเข้าสู่ระบบหลายครั้ง กรุณารอสักครู่');
  end if;

  select data,version into v_data,v_version from private.inventory_state
   where id=true and branch_id=p_branch_id;
  select account into v_user from private.inventory_global_admin
   where id=true and lower(account->>'name')=v_name;
  v_is_global_admin := v_user is not null;
  if v_user is null then
    select value into v_user from jsonb_array_elements(coalesce(v_data->'users','[]'::jsonb))
     where lower(value->>'name')=v_name;
  end if;

  if v_user is null or coalesce(v_user->>'pin','')<>p_pin_hash
     or coalesce((v_user->>'active')::boolean,false) is not true then
    update private.inventory_login_failures
       set failures=case when failures>=4 then 0 else failures+1 end,
           blocked_until=case when failures>=4 then now()+interval '60 seconds' else null end
     where branch_id=p_branch_id and username=v_name;
    return jsonb_build_object('ok',false,'error','ชื่อผู้ใช้หรือรหัสไม่ถูกต้อง');
  end if;

  delete from private.inventory_login_failures where branch_id=p_branch_id and username=v_name;

  if not v_is_global_admin then
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_name,0));
    delete from private.inventory_sessions
     where lower(username)=v_name and branch_id<>p_branch_id;
  end if;

  v_token:=encode(extensions.gen_random_bytes(32),'hex');
  insert into private.inventory_sessions(token_hash,username,branch_id,expires_at)
  values(encode(extensions.digest(v_token,'sha256'),'hex'),v_name,p_branch_id,
         private.inventory_next_saturday_midnight());

  return jsonb_build_object('ok',true,'token',v_token,'state',public.api_safe_state(v_data),
    'me',v_user-'pin','version',v_version,'branch',v_branch);
end
$function$;
