-- Restrict direct access to the private profile-version metadata.
alter table private.inventory_job_profile_versions enable row level security;
revoke all on table private.inventory_job_profile_versions from public, anon, authenticated;
revoke all on function public.api_job_profiles_get(text) from public;
revoke all on function public.api_job_profile_set(text,text,text) from public;
grant execute on function public.api_job_profiles_get(text) to anon, authenticated;
grant execute on function public.api_job_profile_set(text,text,text) to anon, authenticated;
