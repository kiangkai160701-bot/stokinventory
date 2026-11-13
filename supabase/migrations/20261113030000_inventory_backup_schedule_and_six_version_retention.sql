-- Stock Inventory automatic backup policy
-- Bangkok time 08:00-21:00 hourly; pg_cron runs in GMT/UTC.
-- Keep only the six newest backups in total.

begin;

create or replace function private.capture_inventory_backup(
  p_reason text default 'scheduled',
  p_created_by text default 'system'
)
returns uuid
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_id uuid;
  v_data jsonb;
  v_count integer;
  v_state_count integer;
begin
  select count(*) into v_count from private.inventory_branches;
  select count(*) into v_state_count
    from private.inventory_branches b
    join private.inventory_state s on s.branch_id = b.id and s.id = true;
  if v_count < 3 or v_state_count <> v_count then
    raise exception 'Backup aborted: expected state for every branch (branches %, states %)', v_count, v_state_count;
  end if;

  select jsonb_build_object(
    'format', 'stokinventory-full-backup-v1',
    'created_at', now(),
    'branches', jsonb_agg(
      jsonb_build_object(
        'id', b.id,
        'name', b.name,
        'active', b.active,
        'version', s.version,
        'updated_at', s.updated_at,
        'data', s.data
      ) order by b.created_at, b.id
    )
  ) into v_data
  from private.inventory_branches b
  join private.inventory_state s on s.branch_id = b.id and s.id = true;

  insert into private.inventory_full_backups(reason, branch_count, data, created_by)
  values (coalesce(nullif(p_reason,''),'scheduled'), v_count, v_data, coalesce(nullif(p_created_by,''),'system'))
  returning id into v_id;

  delete from private.inventory_full_backups
  where id not in (
    select id from private.inventory_full_backups
    order by saved_at desc, id desc limit 6
  );

  return v_id;
end;
$function$;

create or replace function public.api_inventory_backup_list(p_token text)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_name text;
  v_items jsonb;
  v_latest timestamptz;
  v_branches jsonb;
begin
  select username into v_name
  from private.inventory_sessions
  where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and expires_at > now();

  if v_name is null then
    return jsonb_build_object('ok',false,'error','เซสชันหมดอายุหรือไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่');
  end if;

  select coalesce(jsonb_agg(jsonb_build_object('id',id,'name',name) order by created_at,id),'[]'::jsonb)
    into v_branches from private.inventory_branches;
  select max(saved_at) into v_latest from private.inventory_full_backups;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id', id, 'saved_at', saved_at, 'reason', reason,
    'branch_count', branch_count, 'size_bytes', octet_length(data::text),
    'created_by', created_by
  ) order by saved_at desc, id desc), '[]'::jsonb)
  into v_items
  from (
    select id, saved_at, reason, branch_count, data, created_by
    from private.inventory_full_backups
    order by saved_at desc, id desc limit 6
  ) recent_backups;

  return jsonb_build_object(
    'ok',true, 'automatic',true, 'interval_minutes',60,
    'retention_hours',6, 'retention_count',6,
    'latest_at',v_latest, 'branches',v_branches, 'items',v_items
  );
end;
$function$;

do $block$
declare v_job_id bigint;
begin
  select jobid into v_job_id
  from cron.job where jobname = 'inventory-full-backup-hourly';
  if v_job_id is null then
    raise exception 'Expected cron job inventory-full-backup-hourly was not found';
  end if;
  perform cron.alter_job(
    job_id := v_job_id,
    schedule := '0 1-14 * * *',
    active := true
  );
end;
$block$;

delete from private.inventory_full_backups
where id not in (
  select id from private.inventory_full_backups
  order by saved_at desc, id desc limit 6
);

commit;