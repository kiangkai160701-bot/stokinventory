-- เพิ่มสถานะผู้ใช้งานออนไลน์ โดยไม่เปลี่ยนหรือลบข้อมูลสต็อกเดิม
alter table private.inventory_sessions add column if not exists last_seen timestamptz;
alter table private.inventory_sessions alter column last_seen set default now();

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

revoke all on function public.api_presence_tick(text) from public;
grant execute on function public.api_presence_tick(text) to anon, authenticated;
notify pgrst, 'reload schema';
