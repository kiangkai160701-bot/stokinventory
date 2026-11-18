create or replace function public.api_announcement_version_get(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_auth jsonb;
  v_branch_id uuid;
  v_version text;
begin
  -- Reuse the lightweight session/version validator; do not load full inventory state.
  v_auth := public.api_get_state_version(p_token);
  if coalesce((v_auth->>'ok')::boolean, false) is not true then
    return v_auth;
  end if;

  v_branch_id := (v_auth->'branch'->>'id')::uuid;

  select md5(coalesce(
    string_agg(
      concat_ws('|', id::text, message, array_to_string(branch_ids, ','), expires_at::text),
      E'\n' order by id::text
    ),
    'no-active-announcement'
  ))
  into v_version
  from public.announcements
  where cancelled_at is null
    and expires_at > now()
    and v_branch_id::text = any(branch_ids);

  return jsonb_build_object('ok', true, 'version', v_version);
end;
$function$;

revoke all on function public.api_announcement_version_get(text) from public;
grant execute on function public.api_announcement_version_get(text) to anon, authenticated;
