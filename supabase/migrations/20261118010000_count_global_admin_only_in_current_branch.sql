-- Show the global administrator as online only in the branch represented
-- by the token making the cross-branch presence-count request.
create or replace function public.api_presence_branch_counts(p_token text)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_username text;
  v_branch_id uuid;
  v_is_global_admin boolean := false;
  v_counts jsonb;
begin
  update private.inventory_sessions
     set last_seen = now()
   where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
     and expires_at > now()
  returning username, branch_id into v_username, v_branch_id;

  if v_username is null then
    return jsonb_build_object('ok', false, 'error', 'หมดเวลาการใช้งาน กรุณาเข้าสู่ระบบใหม่');
  end if;

  select exists (
    select 1 from private.inventory_global_admin
     where id = true and lower(account->>'name') = lower(v_username)
  ) into v_is_global_admin;

  if not v_is_global_admin then
    return jsonb_build_object('ok', false, 'error', 'เฉพาะผู้ดูแลหลักเท่านั้น');
  end if;

  select coalesce(
    jsonb_agg(jsonb_build_object(
      'branch_id', b.id,
      'online', coalesce(o.n, 0) + case when b.id = v_branch_id then 1 else 0 end
    ) order by b.name),
    '[]'::jsonb
  )
  into v_counts
  from private.inventory_branches b
  left join (
    select s.branch_id, count(distinct s.username)::int as n
      from private.inventory_sessions s
     where s.expires_at > now()
       and s.last_seen > now() - interval '50 seconds'
       and not exists (
         select 1 from private.inventory_global_admin ga
          where ga.id = true and lower(ga.account->>'name') = lower(s.username)
       )
     group by s.branch_id
  ) o on o.branch_id = b.id
  where b.active;

  return jsonb_build_object('ok', true, 'counts', v_counts);
end
$function$;
