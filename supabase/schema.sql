-- =====================================================================
-- TimeCool · โครงสร้างฐานข้อมูลสำหรับ Supabase
-- วิธีใช้: Supabase › SQL Editor › New query › วางทั้งไฟล์ › Run
-- รันซ้ำได้ (ใช้ if not exists / or replace)
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- ตาราง ----------
create table if not exists public.employees (
  id          uuid primary key default gen_random_uuid(),
  code        text not null unique,
  name        text not null,
  dept        text not null default '',
  position    text not null default '',
  emp_type    text not null default 'monthly' check (emp_type in ('monthly','daily')),
  hire_date   date,
  active      boolean not null default true,
  role        text not null default 'employee' check (role in ('employee','manager')),
  user_id     uuid unique references auth.users(id) on delete set null,
  login_seq   int not null default 0,
  created_at  timestamptz not null default now()
);

-- รหัสเปิดใช้งาน (ใช้ลงทะเบียนครั้งแรก) แยกตารางไว้ ให้เฉพาะผู้จัดการเห็น
create table if not exists public.employee_secrets (
  emp_id      uuid primary key references public.employees(id) on delete cascade,
  activation  text not null
);

create table if not exists public.config (
  id    int primary key default 1 check (id = 1),
  data  jsonb not null default '{}'::jsonb
);

create table if not exists public.holidays (
  date  date primary key,
  name  text not null
);

create table if not exists public.records (
  id        uuid primary key default gen_random_uuid(),
  emp_id    uuid not null references public.employees(id),
  emp_name  text,
  type      text not null check (type in ('in','out')),
  ts        timestamptz not null default now(),
  date      date not null default (now() at time zone 'Asia/Bangkok')::date,
  photo     text,
  lat double precision, lng double precision, acc double precision,
  gps       text,
  dist      double precision
);
create index if not exists records_date_idx on public.records(date);
create index if not exists records_emp_date_idx on public.records(emp_id, date);

create table if not exists public.requests (
  id          uuid primary key default gen_random_uuid(),
  emp_id      uuid not null references public.employees(id),
  emp_name    text,
  kind        text not null check (kind in ('leave','ot')),
  leave_type  text,
  from_date   date not null,
  to_date     date not null,
  hours       numeric,
  days        numeric,
  reason      text not null default '',
  flags       jsonb not null default '[]'::jsonb,
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at  timestamptz not null default now(),
  decided_at  timestamptz,
  decided_by  uuid references public.employees(id)
);
create index if not exists requests_emp_idx on public.requests(emp_id);

-- ---------- ฟังก์ชันช่วย ----------
create or replace function public.my_emp_id() returns uuid
language sql stable security definer set search_path = public as $$
  select id from employees where user_id = auth.uid() and active
$$;

create or replace function public.is_manager() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from employees where user_id = auth.uid() and role = 'manager' and active)
$$;

create or replace function public.new_activation() returns text
language sql volatile set search_path = public, extensions as $$
  select upper(encode(extensions.gen_random_bytes(4), 'hex'))
$$;

-- อีเมลภายในที่ใช้ล็อกอิน (พนักงานไม่ต้องรู้ ใช้แค่รหัสพนักงาน + PIN)
create or replace function public.login_email(p_code text) returns text
language sql stable security definer set search_path = public as $$
  select 'e' || lower(regexp_replace(code, '[^a-zA-Z0-9]', '', 'g')) || '-' || login_seq || '@staff.coolinnotech.com'
  from employees where code = trim(p_code) and active
$$;

-- ตรวจรหัสเปิดใช้งานก่อนสมัคร
create or replace function public.check_activation(p_code text, p_activation text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from employees e join employee_secrets s on s.emp_id = e.id
    where e.code = trim(p_code) and e.active and e.user_id is null
      and s.activation = upper(trim(p_activation))
  )
$$;

-- ผูกบัญชีที่เพิ่งสมัครเข้ากับพนักงาน
create or replace function public.claim_account(p_code text, p_activation text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_emp employees;
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  select * into v_emp from employees where code = trim(p_code) and active for update;
  if not found then raise exception 'code_not_found'; end if;
  if v_emp.user_id is not null then raise exception 'already_claimed'; end if;
  if not exists (select 1 from employee_secrets where emp_id = v_emp.id and activation = upper(trim(p_activation))) then
    raise exception 'bad_activation';
  end if;
  if (select email from auth.users where id = auth.uid()) is distinct from login_email(p_code) then
    raise exception 'email_mismatch';
  end if;
  update employees set user_id = auth.uid() where id = v_emp.id;
  update employee_secrets set activation = new_activation() where emp_id = v_emp.id;
  return v_emp.id;
end $$;

-- ผู้จัดการรีเซ็ตบัญชีพนักงาน (ลืม PIN / เปลี่ยนเครื่อง) ได้รหัสเปิดใช้งานใหม่
create or replace function public.reset_account(p_emp uuid) returns text
language plpgsql security definer set search_path = public as $$
declare v text := new_activation();
begin
  if not is_manager() then raise exception 'forbidden'; end if;
  if p_emp = my_emp_id() then raise exception 'cannot_reset_self'; end if;
  update employees set user_id = null, login_seq = login_seq + 1 where id = p_emp;
  insert into employee_secrets(emp_id, activation) values (p_emp, v)
    on conflict (emp_id) do update set activation = excluded.activation;
  return v;
end $$;

revoke all on function public.login_email(text), public.check_activation(text,text),
  public.claim_account(text,text), public.reset_account(uuid), public.new_activation() from public;
grant execute on function public.login_email(text), public.check_activation(text,text) to anon, authenticated;
grant execute on function public.claim_account(text,text), public.reset_account(uuid) to authenticated;

-- ---------- ทริกเกอร์ ----------
create or replace function public.employees_after_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into employee_secrets(emp_id, activation) values (new.id, new_activation()) on conflict do nothing;
  return new;
end $$;
drop trigger if exists trg_employees_secret on public.employees;
create trigger trg_employees_secret after insert on public.employees
  for each row execute function public.employees_after_insert();

-- เวลาลงงานใช้เวลาของเซิร์ฟเวอร์เสมอ แก้เวลาในมือถือไม่ได้
create or replace function public.records_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.ts := now();
  new.date := (now() at time zone 'Asia/Bangkok')::date;
  select name into new.emp_name from employees where id = new.emp_id;
  return new;
end $$;
drop trigger if exists trg_records_insert on public.records;
create trigger trg_records_insert before insert on public.records
  for each row execute function public.records_before_insert();

create or replace function public.requests_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.status := 'pending';
  new.created_at := now();
  new.decided_at := null;
  new.decided_by := null;
  select name into new.emp_name from employees where id = new.emp_id;
  return new;
end $$;
drop trigger if exists trg_requests_insert on public.requests;
create trigger trg_requests_insert before insert on public.requests
  for each row execute function public.requests_before_insert();

create or replace function public.requests_before_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.status is distinct from old.status then
    new.decided_at := now();
    new.decided_by := my_emp_id();
  end if;
  return new;
end $$;
drop trigger if exists trg_requests_update on public.requests;
create trigger trg_requests_update before update on public.requests
  for each row execute function public.requests_before_update();

-- ---------- สิทธิ์การเข้าถึง (Row Level Security) ----------
alter table public.employees        enable row level security;
alter table public.employee_secrets enable row level security;
alter table public.config           enable row level security;
alter table public.holidays         enable row level security;
alter table public.records          enable row level security;
alter table public.requests         enable row level security;

do $$ declare p record; begin
  for p in select policyname, tablename from pg_policies where schemaname = 'public'
    and tablename in ('employees','employee_secrets','config','holidays','records','requests')
  loop execute format('drop policy %I on public.%I', p.policyname, p.tablename); end loop;
end $$;

-- พนักงาน: เห็นข้อมูลตัวเอง · ผู้จัดการ: เห็นและแก้ได้ทั้งหมด
create policy employees_read   on public.employees for select to authenticated using (user_id = auth.uid() or is_manager());
create policy employees_insert on public.employees for insert to authenticated with check (is_manager());
create policy employees_update on public.employees for update to authenticated using (is_manager()) with check (is_manager());
create policy employees_delete on public.employees for delete to authenticated using (is_manager());

create policy secrets_manager on public.employee_secrets for all to authenticated using (is_manager()) with check (is_manager());

-- ตั้งค่าและวันหยุด: ทุกคนอ่านได้ · ผู้จัดการแก้ได้
create policy config_read   on public.config for select to authenticated using (true);
create policy config_insert on public.config for insert to authenticated with check (is_manager());
create policy config_update on public.config for update to authenticated using (is_manager()) with check (is_manager());

create policy holidays_read   on public.holidays for select to authenticated using (true);
create policy holidays_insert on public.holidays for insert to authenticated with check (is_manager());
create policy holidays_update on public.holidays for update to authenticated using (is_manager()) with check (is_manager());
create policy holidays_delete on public.holidays for delete to authenticated using (is_manager());

-- ลงเวลา: พนักงานบันทึกและดูของตัวเอง · ผู้จัดการดูได้ทั้งหมด แก้/ลบได้
create policy records_read   on public.records for select to authenticated using (emp_id = my_emp_id() or is_manager());
create policy records_insert on public.records for insert to authenticated with check (emp_id = my_emp_id());
create policy records_update on public.records for update to authenticated using (is_manager()) with check (is_manager());
create policy records_delete on public.records for delete to authenticated using (is_manager());

-- คำขอลา/OT: พนักงานส่งและดูของตัวเอง · ผู้จัดการอนุมัติ
create policy requests_read   on public.requests for select to authenticated using (emp_id = my_emp_id() or is_manager());
create policy requests_insert on public.requests for insert to authenticated with check (emp_id = my_emp_id());
create policy requests_update on public.requests for update to authenticated using (is_manager()) with check (is_manager());
create policy requests_delete on public.requests for delete to authenticated using (is_manager());

-- ---------- อัปเดตแบบเรียลไทม์ ----------
do $$ declare t text; begin
  foreach t in array array['employees','config','holidays','records','requests'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
