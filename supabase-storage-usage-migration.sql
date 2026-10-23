-- Adds a secure RPC for the settings page to read real database size.
-- Default quota is the Supabase Free-plan database quota (500 MiB).
-- If this project is on another plan, update v_quota_bytes to that plan's limit.

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

