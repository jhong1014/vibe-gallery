-- 바이브코딩 갤러리: 학생 수정 비밀번호 + 교사 평가 점수(30/22/14/6)
-- Supabase 대시보드 → SQL Editor 에 통째로 붙여넣고 Run. (기존 작품은 그대로 유지돼요)

alter table public.gallery_works add column if not exists updated_at timestamptz;

-- 학생 수정 비밀번호(해시) — 외부에서 읽을 수 없음
create table if not exists public.gallery_owner_pw (
  work_id bigint primary key references public.gallery_works(id) on delete cascade,
  pw_hash text not null
);
alter table public.gallery_owner_pw enable row level security;
revoke all on public.gallery_owner_pw from anon, authenticated;

-- 교사 평가 점수 — 외부에서 읽을 수 없음
create table if not exists public.gallery_scores (
  work_id bigint primary key references public.gallery_works(id) on delete cascade,
  score int not null check (score in (30, 22, 14, 6)),
  updated_at timestamptz not null default now()
);
alter table public.gallery_scores enable row level security;
revoke all on public.gallery_scores from anon, authenticated;

create or replace function public.gallery_is_admin(p_pw text)
returns boolean language sql stable security definer set search_path = public, extensions
as $$ select exists (select 1 from gallery_admin where pw_hash = crypt(coalesce(p_pw,''), pw_hash)) $$;

create or replace function public.gallery_check_owner(p_id bigint, p_pw text)
returns boolean language sql stable security definer set search_path = public, extensions
as $$ select exists (select 1 from gallery_owner_pw o where o.work_id = p_id and o.pw_hash = crypt(coalesce(p_pw,''), o.pw_hash))
          or gallery_is_admin(p_pw) $$;

create or replace function public.gallery_upload(p_title text, p_author text, p_desc text, p_html text, p_pw text)
returns jsonb language plpgsql security definer set search_path = public, extensions
as $$
declare r gallery_works;
begin
  if char_length(coalesce(p_pw,'')) < 4 then raise exception '비밀번호는 4자 이상'; end if;
  insert into gallery_works (title, author, description, html)
  values (trim(p_title), trim(p_author), nullif(trim(p_desc),''), p_html)
  returning * into r;
  insert into gallery_owner_pw (work_id, pw_hash) values (r.id, crypt(p_pw, gen_salt('bf')));
  return jsonb_build_object('id', r.id, 'title', r.title, 'author', r.author, 'description', r.description,
                            'likes', r.likes, 'created_at', r.created_at, 'updated_at', r.updated_at);
end $$;

create or replace function public.gallery_update(p_id bigint, p_pw text, p_title text, p_author text, p_desc text, p_html text)
returns jsonb language plpgsql security definer set search_path = public, extensions
as $$
declare r gallery_works;
begin
  if not gallery_check_owner(p_id, p_pw) then return null; end if;
  update gallery_works set
    title = trim(p_title), author = trim(p_author), description = nullif(trim(p_desc),''),
    html = coalesce(nullif(p_html,''), html), updated_at = now()
  where id = p_id returning * into r;
  return jsonb_build_object('id', r.id, 'title', r.title, 'author', r.author, 'description', r.description,
                            'likes', r.likes, 'created_at', r.created_at, 'updated_at', r.updated_at);
end $$;

create or replace function public.gallery_delete(p_id bigint, p_pw text)
returns boolean language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not gallery_check_owner(p_id, p_pw) then return false; end if;
  delete from gallery_works where id = p_id;
  return true;
end $$;

create or replace function public.gallery_set_score(p_id bigint, p_score int, p_pw text)
returns boolean language plpgsql security definer set search_path = public, extensions
as $$
begin
  if not gallery_is_admin(p_pw) then return false; end if;
  if p_score is null then
    delete from gallery_scores where work_id = p_id;
  else
    insert into gallery_scores (work_id, score) values (p_id, p_score)
    on conflict (work_id) do update set score = excluded.score, updated_at = now();
  end if;
  return true;
end $$;

create or replace function public.gallery_get_scores(p_pw text)
returns table (work_id bigint, score int) language plpgsql stable security definer set search_path = public, extensions
as $$
begin
  if not gallery_is_admin(p_pw) then return; end if;
  return query select s.work_id, s.score from gallery_scores s;
end $$;

grant execute on function public.gallery_upload(text,text,text,text,text),
  public.gallery_update(bigint,text,text,text,text,text),
  public.gallery_check_owner(bigint,text),
  public.gallery_set_score(bigint,int,text),
  public.gallery_get_scores(text) to anon, authenticated;
