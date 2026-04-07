-- BountyScope — Supabase Schema
-- Run this in your Supabase SQL editor

-- ── Targets ────────────────────────────────────────────────────
create table if not exists targets (
  id            uuid primary key default gen_random_uuid(),
  slug          text not null unique,
  name          text,
  author        text,
  version       text,
  install_count integer,
  last_updated  text,
  active_installs_raw text,
  repo_status   text default 'active', -- active | closed | unknown
  in_scope      boolean,
  scope_tier    text,                  -- standard | resourceful | 1337 | out_of_scope
  scope_notes   text,
  status        text default 'queued', -- queued | scanning | reviewed | reported | paid | dismissed
  priority      text default 'medium', -- low | medium | high
  notes         text,
  wordfence_cves jsonb default '[]',
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

-- ── Findings ───────────────────────────────────────────────────
create table if not exists findings (
  id              uuid primary key default gen_random_uuid(),
  target_id       uuid references targets(id) on delete cascade,
  slug            text not null,
  vuln_type       text,               -- csrf | missing_auth | xss | sqli | etc
  cwe             text,
  severity        text,               -- critical | high | medium | low | info
  cvss_score      numeric(3,1),
  cvss_vector     text,
  affected_files  jsonb default '[]',
  code_evidence   jsonb default '[]', -- [{file, line, snippet}]
  poc_html        text,
  description     text,
  remediation     text,
  status          text default 'draft', -- draft | confirmed | submitted | accepted | rejected | duplicate
  bounty_estimate numeric(10,2),
  bounty_paid     numeric(10,2),
  submitted_at    timestamptz,
  created_at      timestamptz default now(),
  updated_at      timestamptz default now()
);

-- ── Scans ──────────────────────────────────────────────────────
create table if not exists scans (
  id          uuid primary key default gen_random_uuid(),
  target_id   uuid references targets(id) on delete cascade,
  slug        text not null,
  scan_type   text default 'csrf',
  results     jsonb default '{}',
  file_count  integer default 0,
  hit_count   integer default 0,
  duration_ms integer,
  scanned_at  timestamptz default now()
);

-- ── Updated_at trigger ─────────────────────────────────────────
create or replace function update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger targets_updated_at
  before update on targets
  for each row execute function update_updated_at();

create trigger findings_updated_at
  before update on findings
  for each row execute function update_updated_at();

-- ── Indexes ────────────────────────────────────────────────────
create index if not exists idx_targets_slug     on targets(slug);
create index if not exists idx_targets_status   on targets(status);
create index if not exists idx_findings_target  on findings(target_id);
create index if not exists idx_findings_status  on findings(status);
create index if not exists idx_scans_target     on scans(target_id);
