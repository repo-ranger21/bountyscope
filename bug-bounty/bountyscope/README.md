# BountyScope

**WordPress Bug Bounty Research Workstation** — [@lucius-log](https://github.com/repo-ranger21)

A unified CLI + web dashboard for scoping, scanning, and tracking WordPress plugin vulnerabilities through the Wordfence Bug Bounty Program.

---

## Modules

| Module | What it does |
|---|---|
| **Scope Checker** | Hits WordPress.org API + Wordfence Intel. Checks install count, existing CVEs, and scope eligibility for your researcher tier before you invest time on a target. |
| **CSRF Scanner** | Downloads a plugin zip, extracts it, and runs full static analysis across all PHP files — AJAX handlers, admin POST handlers, state changes, raw `$_POST` consumption, and nonce verification presence. Auto-creates draft findings for confirmed hits. |
| **Target Tracker** | Supabase-backed pipeline board. Targets auto-populate from scope checks and scans. Update status (queued → reported → paid), track bounty estimates, and monitor your full research pipeline. |

---

## Stack

- **Backend:** FastAPI + Python 3.11+
- **Frontend:** React + Vite + Tailwind CSS
- **CLI:** Click + Rich (shares backend services)
- **Database:** Supabase (PostgreSQL)

---

## Setup

### 1. Clone

```bash
git clone https://github.com/repo-ranger21/bountyscope.git
cd bountyscope
```

### 2. Supabase

1. Create a new project at [supabase.com](https://supabase.com)
2. Go to **SQL Editor** and run `supabase/schema.sql`
3. Copy your project URL and anon key

### 3. Environment

```bash
cp .env.example .env
# Fill in SUPABASE_URL, SUPABASE_KEY, RESEARCHER_TIER
```

### 4. Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd ..
uvicorn backend.main:app --reload --port 8000
```

API docs: `http://localhost:8000/docs`

### 5. Frontend

```bash
cd frontend
npm install

# Create frontend env
echo "VITE_API_URL=http://localhost:8000/api" > .env.local

npm run dev
```

Dashboard: `http://localhost:5173`

### 6. CLI

```bash
cd backend
pip install -r requirements.txt   # if not already done

# Make executable
chmod +x cli/bountyscope.py

# Add alias (optional)
echo 'alias bountyscope="python /path/to/bountyscope/cli/bountyscope.py"' >> ~/.zshrc
source ~/.zshrc
```

---

## CLI Usage

```bash
# Check if a plugin is in scope before scanning
bountyscope scope contact-form-7
bountyscope scope myanime-widget --tier 1337

# Download and scan a plugin for CSRF vulnerabilities
bountyscope scan favicon-generator
bountyscope scan some-plugin --show-hits

# Manage your target pipeline
bountyscope targets list
bountyscope targets list --status reviewed
bountyscope targets update some-plugin --status reported --priority high
bountyscope targets stats
```

---

## Researcher Tiers

Set `RESEARCHER_TIER` in `.env` to match your current Wordfence status:

| Tier | CSRF / Other Scope Threshold |
|---|---|
| `standard` | 50,000+ installs |
| `resourceful` | 10,000+ installs |
| `1337` | 500+ installs |

All tiers get access to High Threat vulns (RCE, Auth Bypass, Priv Esc) at 25+ installs.

---

## Workflow

```
bountyscope scope <slug>        ← Is it worth my time?
       ↓ in scope + no known CVEs
bountyscope scan <slug>         ← Is it actually vulnerable?
       ↓ likely_vulnerable
Review draft finding in Tracker
       ↓ confirmed
Generate PDF report → Submit to wordfence.com/submit-vulnerability
       ↓ accepted
bountyscope targets update <slug> --status paid
```

---

## Project Structure

```
bountyscope/
├── backend/
│   ├── main.py               FastAPI app entry
│   ├── config.py             Settings + constants
│   ├── database.py           Supabase client
│   ├── routers/
│   │   ├── scope.py          GET /api/scope/{slug}
│   │   ├── scanner.py        POST /api/scanner/scan
│   │   └── targets.py        CRUD /api/targets/
│   └── services/
│       ├── wordpress_api.py  WordPress.org Plugin API
│       ├── wordfence_api.py  Wordfence Intel API + bounty estimator
│       └── csrf_scanner.py   Static analysis engine
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── pages/
│           ├── ScopeChecker.tsx
│           ├── Scanner.tsx
│           └── Tracker.tsx
├── cli/
│   └── bountyscope.py        Click + Rich CLI
├── supabase/
│   └── schema.sql            DB schema (run once)
├── .env.example
├── .gitignore
└── README.md
```

---

## Disclaimer

BountyScope performs **static code analysis only**. No live WordPress sites are accessed. All plugin code is downloaded directly from the official WordPress.org repository. Use responsibly and only against targets you are authorized to test or that are explicitly in scope for a bug bounty program.

---

**Built by [@lucius-log](https://github.com/repo-ranger21) | Lucius Engine**
