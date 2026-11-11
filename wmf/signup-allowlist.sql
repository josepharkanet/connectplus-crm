-- Connect+ CRM: let Supabase signup stay ON (so the app's invite links work)
-- while still refusing strangers. An email may register only if it matches a
-- row in public.signup_allowlist: either the exact address, or a '@domain'
-- suffix row.

create table if not exists public.signup_allowlist (
  pattern    text primary key,
  note       text,
  created_at timestamptz not null default now()
);

comment on table public.signup_allowlist is
  'Who may create a Connect+ CRM account. Rows are either a full email address or a "@domain" suffix. Enforced by auth.enforce_signup_allowlist() on auth.users INSERT.';

alter table public.signup_allowlist enable row level security;
revoke all on public.signup_allowlist from anon, authenticated;
-- no policies on purpose: only postgres / service_role can read or write it

insert into public.signup_allowlist (pattern, note) values
  ('@worldmalayaleefederation.com', 'WMF primary domain'),
  ('@wmfglobal.org',                'WMF global domain'),
  ('@wmfmalaysia.com.my',           'WMF Malaysia domain')
on conflict (pattern) do nothing;

create or replace function auth.enforce_signup_allowlist()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $fn$
declare
  e text := lower(coalesce(new.email, ''));
begin
  -- phone-only / anonymous users carry no email: leave them alone
  if e = '' then
    return new;
  end if;

  if exists (
    select 1
    from public.signup_allowlist a
    where lower(a.pattern) = e
       or (left(a.pattern, 1) = '@' and e like ('%' || lower(a.pattern)))
  ) then
    return new;
  end if;

  raise exception 'signup_not_allowed: % is not on the Connect+ CRM allowlist', e
    using errcode = '22023';
end;
$fn$;

alter function auth.enforce_signup_allowlist() owner to supabase_admin;

drop trigger if exists enforce_signup_allowlist on auth.users;
create trigger enforce_signup_allowlist
  before insert on auth.users
  for each row execute function auth.enforce_signup_allowlist();
