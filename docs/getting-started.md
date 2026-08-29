# Getting Started with SPECTRE OSINT

[English](getting-started.md) | [Português 🇧🇷](getting-started.pt-BR.md)

SPECTRE is a passive-first, localhost public OSINT workstation designed for single-operator intelligence collection and conservative identity correlation.

---

## System Requirements

- **Python:** `3.12` or `3.13`
- **Operating Systems:** Linux (Ubuntu/Debian recommended), macOS, Windows 11 (native or via WSL2)
- **Browser (Optional):** Google Chrome / Chromium (required only for authenticated-public sessions)
- **Local Search (Optional):** SearXNG running on loopback (`http://127.0.0.1:<port>`)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
```

### 2. Create and Activate Virtual Environment

**Linux / macOS / WSL2:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

### 3. Install SPECTRE

```bash
pip install -e .
```

*For development and running tests, install with dev dependencies:*
```bash
pip install -e ".[dev]"
```

---

## Environment Configuration

SPECTRE reads configuration from environment variables and `.env` in the project root.

```bash
cp .env.example .env
chmod 600 .env  # on POSIX systems
```

### Key Configuration Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SPECTRE_DATA_DIR` | `./data` | SQLite database and HTTP cache directory |
| `SPECTRE_REPORTS_DIR` | `./reports` | Export directory for HTML, JSON, MD, CSV, GraphML |
| `SPECTRE_LOGS_DIR` | `./logs` | Application logs directory |
| `SPECTRE_WEB_HOST` | `127.0.0.1` | Dashboard host interface (binds loopback only) |
| `SPECTRE_ALLOW_PUBLIC_BIND` | `false` | Explicit safety override to allow non-loopback bind |
| `SPECTRE_MAX_CONCURRENCY` | `8` | Max concurrent HTTP requests for catalog sweep |
| `SPECTRE_PIVOT_BUDGET` | `8` | Outer runner auto-pivot cap (IP/Domain) |
| `SPECTRE_SEARCH_QUERY_BUDGET` | `12` | Search planner query budget |
| `SPECTRE_SEARCH_MAX_PIVOTS` | `25` | Search intelligence pivot budget |
| `SPECTRE_SEARCH_MAX_DEPTH` | `2` | Search intelligence discovery depth |
| `SPECTRE_BROWSER_BACKEND` | `playwright` | Browser engine: `playwright` or `chrome` (CDP) |
| `SPECTRE_SSRF_ENABLED` | `true` | Private IP address filtering policy |
| `SEARXNG_URL` | *(unset)* | Optional loopback SearXNG instance URL |

---

## Diagnostic Check: `spectre doctor`

Before running investigations, verify your installation:

```bash
spectre doctor
```

```text
SPECTRE DOCTOR
Core
  Python                   3.13.x           OK
  SPECTRE                  0.1.0b1          OK
  Database                 SQLite           OK
  Database writable        OK               OK
  Reports directory        OK               OK
Browser
  Chrome/Chromium          detected         OK
  Chrome CDP               inactive         OPTIONAL
Search
  SearXNG                  missing          OPTIONAL
API providers
  VirusTotal               NOT CONFIGURED   OPTIONAL
Security
  Bind address             127.0.0.1        OK
  Secrets redaction        OK               OK
  SSRF policy              enabled          OK
Overall: READY WITH OPTIONAL FEATURES MISSING
```

> [!NOTE]
> `spectre doctor` never starts an investigation, never logs into services, and never exposes plaintext secrets.
> Missing optional providers (like VirusTotal or SearXNG) are marked `OPTIONAL` and will **not** block normal operations.

---

## Launching the Workstation GUI

Start the localhost web dashboard:

```bash
spectre dashboard
# or
spectre web
```

Open your browser at `http://127.0.0.1:8000`.

Features available in the GUI:
- **Live Dossier:** View real-time investigation findings, catalog checks, and mention provenance.
- **Interactive Graph:** Visual cluster of correlated identities and observed relationships.
- **Evidence Drawer:** Inspect raw HTTP status codes, extraction rules, and novelty classifications.
- **Session Manager:** Audit active authenticated-public browser profiles without exposing cookies.

---

## Running Your First Investigation via CLI

Investigate a public username target:

```bash
spectre username alice_osint
```

With additional operator leads (aliases, full name, seed email, personal website):

```bash
spectre username alice_osint \
  --alias alice-sec \
  --name "Alice Example" \
  --email alice@example.com \
  --website alice.example
```

---

## Next Steps

- Explore the [Evidence Model](evidence-model.md) to understand status classifications and scoring.
- Learn about [Search Intelligence & Discovery](search-discovery.md).
- Configure [Authenticated Public Sessions](authenticated-public.md).
- Consult the full [CLI Reference](cli-reference.md).
