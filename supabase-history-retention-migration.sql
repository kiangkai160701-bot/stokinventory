-- เก็บประวัติย้อนหลัง 14 วันโดยไม่จำกัดจำนวนรายการ
-- รันครั้งเดียวใน Supabase SQL Editor หลังสำรองข้อมูลที่ต้องการเก็บไว้
begin;

-- ลบรายการที่เก่ากว่า 14 วันจากทุกสาขา
update private.inventory_state s
set data = jsonb_set(
      s.data,
      '{log}',
      coalesce((
        select jsonb_agg(entry order by (entry->>'ts')::numeric desc)
        from jsonb_array_elements(coalesce(s.data->'log', '[]'::jsonb)) entry
        where case
          when coalesce((entry->>'ts') ~ '^[0-9]+([.][0-9]+)?$', false)
            then (entry->>'ts')::numeric >= extract(epoch from (now() - interval '14 days')) * 1000
          else false
        end
      ), '[]'::jsonb),
      true
    ),
    version = s.version + 1,
    updated_at = now()
where jsonb_typeof(s.data->'log') = 'array'
  and exists (
    select 1
    from jsonb_array_elements(coalesce(s.data->'log', '[]'::jsonb)) entry
    where case
      when coalesce((entry->>'ts') ~ '^[0-9]+([.][0-9]+)?$', false)
        then (entry->>'ts')::numeric < extract(epoch from (now() - interval '14 days')) * 1000
      else true
    end
  );

-- อัปเดต api_sync ที่มีอยู่โดยเอาขีดจำกัด 500 รายการออก
-- และกรองประวัติให้เหลือเฉพาะ 14 วันล่าสุด
do $migration$
declare
  v_definition text;
  v_updated_definition text;
begin
  select pg_get_functiondef('public.api_sync(text,jsonb,jsonb)'::regprocedure)
    into v_definition;

  if v_definition is null then
    raise exception 'ไม่พบฟังก์ชัน public.api_sync(text,jsonb,jsonb)';
  end if;

  v_updated_definition := regexp_replace(
    v_definition,
    'as x\(item,ord\) order by ord limit 500',
    $$as x(item,ord) where case
         when coalesce((item->>'ts') ~ '^[0-9]+([.][0-9]+)?$', false)
           then (item->>'ts')::numeric >= extract(epoch from (now() - interval '14 days')) * 1000
         else false
       end
       order by ord$$,
    'gi'
  );

  if v_updated_definition = v_definition then
    raise exception 'ไม่พบส่วนจำกัด 500 รายการใน api_sync; ไม่มีการเปลี่ยนแปลง';
  end if;

  execute v_updated_definition;
end;
$migration$;

notify pgrst, 'reload schema';
commit;
