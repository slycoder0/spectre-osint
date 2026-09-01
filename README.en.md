<div align="center">

<p align="center">
  <img src="docs/assets/brand/spectre-banner.svg" alt="SPECTRE OSINT Banner" width="100%">
</p>

# SPECTRE OSINT

**Public Intelligence Workstation &bull; Passive-First &bull; Evidence-First**

[🇧🇷 Português](README.md) &nbsp;|&nbsp; [🇺🇸 English](#)

[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13-38bdf8?style=flat-square&logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-22d3ee?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-0.1.0b1%20Beta-0ea5e9?style=flat-square)](CHANGELOG.md)
[![Interface](https://img.shields.io/badge/Interface-CLI--First-0284c7?style=flat-square)](docs/en/commands.md)
[![Mode](https://img.shields.io/badge/Mode-Passive--First-0369a1?style=flat-square)](docs/concepts/privacy-and-safety.md)
[![Storage](https://img.shields.io/badge/Storage-Local%20(SQLite)-1e293b?style=flat-square)](docs/en/quick-start.md)
[![CI](https://github.com/slycoder0/spectre-osint/actions/workflows/ci.yml/badge.svg)](https://github.com/slycoder0/spectre-osint/actions/workflows/ci.yml)

<p align="center">
  <strong>SPECTRE</strong> is a CLI-first OSINT tool for collecting, structuring, and correlating public digital footprints from usernames, domains, emails, and indicators without laundering guesses into facts.
</p>

</div>

---

## 🎯 What SPECTRE Does

- **Username Intelligence:** Sweeps dozens of public platforms using structured contracts (JSON APIs and HTML signatures) with strict structural verification of profile existence.
- **Search Intelligence & Discovery:** Plans dorking queries across public search engines, discovers candidate profiles, and extracts new investigation pivots.
- **Conservative Identity Correlation:** Evaluates profile overlap across platforms using deterministic weights and biographical conflict detection.
- **Authenticated Public Sessions:** Allows inspection of public metadata on login-walled platforms (e.g. Instagram) via isolated Chromium profiles without storing passwords.
- **Local Artifacts & Graphs:** Generates rich standalone HTML dossiers, machine-readable JSON/Markdown, CSVs, and Relationship Graphs (GraphML).

---

## ⚡ Quick Start

Install and run your first investigation:

### 1. Clone & Set Up Environment

#### Windows (PowerShell)
```powershell
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

#### Linux / macOS
```bash
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Verify Health

```bash
spectre doctor
```

### 3. Run Your First Investigation

```bash
spectre username alice_osint
```

Investigation findings will be output to your terminal and saved locally under `reports/`.

---

## 🧭 Essential Commands

| Intent | Command | Description |
| :--- | :--- | :--- |
| **Check Environment** | `spectre doctor` | Inspects dependencies, SQLite database, and providers without printing secrets. |
| **Investigate Username** | `spectre username <handle>` | Public profile sweep across Site Catalog with metadata extraction. |
| **Investigate Email** | `spectre email <email>` | Format validation, DNS/MX check, and public footprint check. |
| **Investigate Domain** | `spectre domain <domain>` | DNS intelligence, RDAP registration, CT certificates, and fingerprinting. |
| **Investigate IP Address** | `spectre ip <ip>` | IP intelligence, network allocation, and threat footprint. |
| **Full Investigation** | `spectre investigate <target>` | Full pipeline with correlation, entity graph, and standalone HTML report. |
| **Generate Reports** | `spectre report [case]` | Regenerates investigation artifacts (HTML, JSON, Markdown, GraphML). |
| **Authenticated Sessions** | `spectre auth status` | Inspects and manages isolated sessions for login-walled public platforms. |
| **Cache Status** | `spectre cache status` | Displays local cached records and TTL expiration status. |

👉 [Read the English Commands Reference](docs/en/commands.md)

---

## 🛡️ How SPECTRE Avoids False Positives

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CORE EVIDENTIAL RULES                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✖  HTTP 200 ≠ Confirmed Profile        ✖  Same Username ≠ Same Person      │
│  ✖  Operator Input ≠ Observed Fact      ✖  Search Candidate ≠ CONFIRMED     │
│  ✔  Strict Field-Level Provenance       ✔  Conservative Profile Clustering  │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **HTTP 200 does not confirm a profile:** Existence requires matching platform-specific structural fields (JSON identity keys) or verified markup.
2. **Same username is not proof of identity:** Sharing a handle across platforms is an initial lead, never proof of civil identity.
3. **Operator input stays distinct from observed facts:** Leads provided by the investigator are kept strictly separate from web findings.
4. **Search candidates stay candidates:** Discovered search mentions are never automatically promoted to confirmed catalog profiles.

👉 [Read the Evidence Model](docs/concepts/evidence.md) &bull; [Results & Status Dictionary](docs/results.md)

---

## 📚 Documentation

Explore the full documentation suite:

- 🚀 [English Quick Start Guide](docs/en/quick-start.md)
- 💻 [English Commands Reference](docs/en/commands.md)
- 🧠 [Evidence Model & Invariants](docs/concepts/evidence.md)
- 🏗️ [Technical Architecture](docs/technical/architecture.md)
- 🔒 [Privacy & Safety Boundaries](docs/concepts/privacy-and-safety.md)

---

## 🔒 Operational Boundaries

- **Local Execution & Storage:** Database, logs, and reports reside locally on your disk.
- **Passive-First:** Gathers publicly accessible data. The primary workflow requires no paid API keys.
- **Zero Credential Capture:** Authenticated logins are conducted manually by the operator in a visible browser; SPECTRE never asks for or stores passwords.
- **No Exploitation or Evasion:** SPECTRE does not solve CAPTCHAs, spoof TLS fingerprints, or bypass access controls.

---

## 👥 Contributing & License

Contributions are welcome! Please review the [Contribution Guidelines](CONTRIBUTING.md) and [Testing Guide](docs/technical/testing.md).

Distributed under the [MIT License](LICENSE).

---

<div align="center">
  <sub>SPECTRE OSINT &bull; Built for evidence-first digital investigations.</sub>
</div>
