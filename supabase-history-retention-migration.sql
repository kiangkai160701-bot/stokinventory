-- เก็บประวัติย้อนหลัง 6 เดือนโดยไม่จำกัดจำนวนรายการ
-- รันครั้งเดียวใน Supabase SQL Editor หลังสำรองข้อมูลที่ต้องการเก็บไว้
-- รองรับทั้ง api_sync รุ่นเดิมที่จำกัด 500 รายการ และรุ่นที่กรอง 14 วันแล้ว
begin;

-- ลบเฉพาะประวัติที่เก่ากว่า 6 เดือนจากทุกสาขา
update private.inventory_state s
set data = jsonb_set(
      s.data,
      '{log}',
      coalesce((
        select jsonb_agg(entry order by (entry->>'ts')::numeric desc)
        from jsonb_array_elements(coalesce(s.data->'log', '[]'::jsonb)) entry
        where case
          when coalesce((entry->>'ts') ~ '^[0-9]+([.][0-9]+)?$', false)
            then (entry->>'ts')::numeric >= extract(epoch from (now() - interval '6 months')) * 1000
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
        then (entry->>'ts')::numeric < extract(epoch from (now() - interval '6 months')) * 1000
      else true
    end
  );

-- ปรับฟังก์ชันที่ติดตั้งอยู่ให้เก็บประวัติ 6 เดือน และนำเพดาน 500 รายการออก
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

  -- ถ้าเคยติดตั้ง migration 14 วัน ให้ขยายระยะเวลาเป็น 6 เดือน
  v_updated_definition := replace(
    v_definition,
    'interval ''14 days''',
    'interval ''6 months'''
  );

  -- ถ้ายังเป็นรุ่นตั้งต้น ให้เอา LIMIT 500 ออกและใส่เงื่อนไข 6 เดือน
  v_updated_definition := regexp_replace(
    v_updated_definition,
    'as x\(item,ord\) order by ord limit 500',
    $$as x(item,ord) where case
         when coalesce((item->>'ts') ~ '^[0-9]+([.][0-9]+)?$', false)
           then (item->>'ts')::numeric >= extract(epoch from (now() - interval '6 months')) * 1000
         else false
       end
       order by ord$$,
    'gi'
  );

  if v_updated_definition = v_definition
     and position('interval ''6 months''' in v_definition) = 0 then
    raise exception 'ไม่พบรูปแบบ api_sync ที่รองรับ; ไม่มีการเปลี่ยนแปลง';
  end if;

  if v_updated_definition <> v_definition then
    execute v_updated_definition;
  end if;
end;
$migration$;

notify pgrst, 'reload schema';
commit;
