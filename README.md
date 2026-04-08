# BountyScope — WordPress Bug Bounty Workstation

> "Get shit poppin" edition — written by me, for me. @lucius-log / repo-ranger21

---

## What is this?

BountyScope is my personal WordPress bug bounty research station. Three tools in one:

1. **Scope Checker** — paste a plugin slug, instantly know if it's worth hunting (install count thresholds, tier logic, Wordfence + WPScan + Patchstack cross-ref, duplicate risk)
2. **CSRF Scanner** — pulls the plugin source and runs static analysis to find unprotected AJAX handlers, missing nonces, raw `$_POST` usage
3. **Target Tracker** — Supabase-backed pipeline: queue → scan → reviewed → reported → paid

Stack: FastAPI backend, React + Vite + Tailwind frontend, Supabase (Postgres), CLI via Click + Rich.

---

## Prerequisites

Before I touch anything, I need:

- Python 3.11+
- Node 18+
- A [Supabase](https://supabase.com) project (free tier is fine)
- API keys: WPScan, Patchstack (optional but recommended)
- `wpscan` installed (`gem install wpscan`) and `semgrep` (`pip install semgrep`) for the shell pipeline

---

## 1. Clone & orient

```bash
cd ~/bug-bounty/bountyscope
ls
# backend/   frontend/   cli/   supabase/   recon_to_analysis.sh
```

The project root is `~/bug-bounty/bountyscope`. Everything is relative to here.

---

## 2. Set up the backend

```bash
cd ~/bug-bounty/bountyscope

# Create and activate a venv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### Configure environment

Create `.env` in the project root (same level as `backend/`):

```bash
cp .env.example .env   # if it exists, otherwise create it
```

Minimum required variables:

```env
# Supabase
SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key

# API tokens
WPSCAN_API_TOKEN=your-wpscan-token
PATCHSTACK_API_TOKEN=your-patchstack-token   # optional

# Researcher tier — controls install count thresholds
# standard | resourceful | 1337
RESEARCHER_TIER=standard

APP_ENV=development
CORS_ORIGINS=["http://localhost:5173"]
```

Get your tokens:
- WPScan token → [wpscan.io/profile](https://wpscan.com/profile)
- Patchstack token → [patchstack.com](https://patchstack.com) (free tier available)

### Start the API

```bash
# From project root, venv active
uvicorn backend.main:app --reload --port 8000
```

Swagger UI → [http://localhost:8000/docs](http://localhost:8000/docs)

Health check:
```bash
curl http://localhost:8000/api/health
# {"status":"ok","version":"1.0.0","researcher":"@lucius-log"}
```

---

## 3. Set up Supabase

Open my Supabase project → SQL Editor → paste and run the entire contents of:

```
supabase/schema.sql
```

This creates:
- `targets` — plugin pipeline (queued → paid)
- `findings` — individual vulns with CVSS, code evidence, PoC
- `scans` — scan run history and results

---

## 4. Set up the frontend

```bash
cd ~/bug-bounty/bountyscope/frontend
npm install
npm run dev
```

Frontend → [http://localhost:5173](http://localhost:5173)

The UI proxies API calls to `http://localhost:8000`. Make sure the backend is running first.

---

## 5. Use the CLI

The CLI is my main interface for quick scope checks without touching the browser.

```bash
# Activate venv from project root
source ~/bug-bounty/bountyscope/.venv/bin/activate

# Scope check — is this plugin worth hunting?
python cli/bountyscope.py scope contact-form-7

# With tier override
python cli/bountyscope.py scope contact-form-7 --tier 1337

# Raw JSON output (pipe into jq, etc.)
python cli/bountyscope.py scope contact-form-7 --json-out | jq .

# Static CSRF scan against a plugin slug
python cli/bountyscope.py scan contact-form-7

# Target tracker commands
python cli/bountyscope.py targets list
python cli/bountyscope.py targets show <slug>
python cli/bountyscope.py targets stats
```

---

## 6. Run the full recon pipeline (WPScan → Semgrep)

This is the "surgical strike" — scan a live WordPress target, enumerate plugins, pull source, run Semgrep analysis.

```bash
cd ~/bug-bounty/bountyscope

# Full run against a target
./recon_to_analysis.sh https://target.example.com

# Skip WPScan, re-analyze last scan's results
./recon_to_analysis.sh https://target.example.com --skip-wpscan
```

Requires:
- `WPSCAN_API_KEY` set in env or `~/.wpscan/token`
- `wpscan` binary on PATH (`gem install wpscan`)
- `semgrep` on PATH (`pip install semgrep`)

Output lands in `workspace/<timestamp>/` with a `latest_scan` symlink always pointing to the most recent run.

---

## Researcher tier reference

My tier controls the install count floor for "in scope" determination:

| Tier | Other vulns threshold |
|---|---|
| `standard` | 50,000+ active installs |
| `resourceful` | 10,000+ active installs |
| `1337` | 500+ active installs |

High-threat vuln types (RCE, Auth Bypass, Priv Esc, Arbitrary File Upload/Delete, Options Update) and "common dangerous" types (Stored XSS, SQLi) have their own lower thresholds regardless of tier — see `backend/config.py`.

---

## Typical workflow

```
1. Find a plugin slug (Wordfence feed, WPScan DB, gut feel)
2. bountyscope scope <slug>          ← is it worth my time?
3. bountyscope scan <slug>           ← static CSRF/nonce analysis
4. ./recon_to_analysis.sh <url>      ← deep recon if I have a live target
5. Manual verification in browser    ← confirm the finding
6. bountyscope targets update <slug> ← log it in the tracker
7. Write report → submit to HackerOne
```

---

## Project structure

```
bountyscope/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Settings, scope thresholds, CSRF/nonce patterns
│   ├── database.py          # Supabase client
│   ├── routers/
│   │   ├── scope.py         # GET /api/scope/:slug
│   │   ├── scanner.py       # POST /api/scan
│   │   └── targets.py       # CRUD /api/targets
│   └── services/
│       ├── wordpress_api.py  # WordPress.org plugin info
│       ├── wordfence_api.py  # Wordfence Intel CVE lookup + bounty estimates
│       ├── wpscan_api.py     # WPScan vulnerability DB
│       ├── patchstack_api.py # Patchstack vuln DB
│       ├── csrf_scanner.py   # Static CSRF/nonce pattern analysis
│       └── semgrep_scanner.py
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── pages/
│           ├── ScopeChecker.tsx
│           ├── Scanner.tsx
│           └── Tracker.tsx
├── cli/
│   └── bountyscope.py       # Click CLI
├── supabase/
│   └── schema.sql           # Full DB schema — run this first
├── recon_to_analysis.sh     # WPScan → Semgrep pipeline
├── workspace/               # Pipeline output (gitignored)
└── cache/                   # Plugin source cache (gitignored)
```

---

## Common issues

**Backend can't find `backend` module**

Run uvicorn from the project root, not from inside `backend/`:
```bash
cd ~/bug-bounty/bountyscope
uvicorn backend.main:app --reload
```

**Supabase connection errors**

Double-check `SUPABASE_URL` and `SUPABASE_KEY` in `.env`. Use the service role key if the anon key is hitting RLS blocks.

**WPScan rate limits**

Free WPScan API tier is limited. Add your token to `.env` and `~/.wpscan/token` for higher limits.

**Frontend hitting 404 on API calls**

Backend must be on port 8000. Check `frontend/vite.config.ts` for the proxy config.

---

## Hard rules (never skip)

- Only test in-scope, authorized targets
- Own test accounts only — use HackerOne alias `username+target@wearehackerone.com`
- Add `X-HackerOne-Research: lucius-log` header on unauthenticated requests
- Max 100 req/s per endpoint, 10k req/day total
- Stop immediately if I hit real PII or payment data — report the vector, don't save the data
- No DoS, no destructive ops, no persistence

---

*BountyScope — @lucius-log / repo-ranger21*

