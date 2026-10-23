-- Run once in Supabase SQL Editor to enable authorized, scoped resets.
create or replace function public.api_reset_data(p_token text, p_scope text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_name text; v_data jsonb; v_user jsonb; v_version bigint;
begin
  select username into v_name from private.inventory_sessions
    where token_hash = encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex') and expires_at > now();
  if v_name is null then return jsonb_build_object('ok',false,'error','หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่'); end if;
  select data into v_data from private.inventory_state where id=true for update;
  select value into v_user from jsonb_array_elements(v_data->'users') where lower(value->>'name')=lower(v_name);
  if v_user is null or (coalesce((v_user->>'owner')::boolean,false) is not true and coalesce((v_user->'permissions'->>'resetData')::boolean,false) is not true) then
    return jsonb_build_object('ok',false,'error','บัญชีนี้ไม่มีสิทธิ์รีเซ็ตข้อมูล');
  end if;
  if p_scope not in ('products','history','users','all') then return jsonb_build_object('ok',false,'error','ขอบเขตการรีเซ็ตไม่ถูกต้อง'); end if;
  if p_scope in ('products','all') then v_data=jsonb_set(v_data,'{products}','[]'::jsonb); end if;
  if p_scope in ('history','all','users') then v_data=jsonb_set(v_data,'{log}','[]'::jsonb); end if;
  if p_scope='users' then
    select coalesce(jsonb_agg(value),'[]'::jsonb) into v_data
      from jsonb_array_elements(v_data->'users') value where coalesce((value->>'owner')::boolean,false);
    v_data=jsonb_set((select data from private.inventory_state where id=true),'{users}',v_data);
  end if;
  update private.inventory_state set data=v_data,version=version+1,updated_at=now() where id=true returning version into v_version;
  return jsonb_build_object('ok',true,'state',public.api_safe_state(v_data),'version',v_version);
end; $$;
revoke all on function public.api_reset_data(text,text) from public;
grant execute on function public.api_reset_data(text,text) to anon, authenticated;
