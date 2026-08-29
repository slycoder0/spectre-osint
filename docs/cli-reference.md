# SPECTRE CLI Reference Manual

[English](cli-reference.md) | [Português 🇧🇷](cli-reference.pt-BR.md)

SPECTRE provides a rich command-line interface powered by Typer and Rich for running investigations, configuring authenticated sessions, managing cache, and diagnosing installation health.

---

## Command Overview

```text
spectre [OPTIONS] COMMAND [ARGS]...
```

| Command | Purpose |
| :--- | :--- |
| `spectre username` | Main username collection, mention sweep, search intelligence, and identity correlation. |
| `spectre investigate` | Multi-type investigation with automatic entity detection. |
| `spectre email` | Email format analysis, MX records, domain reputation, and breach checks. |
| `spectre domain` | Domain intelligence: DNS, WHOIS/RDAP, Certificate Transparency (crt.sh). |
| `spectre ip` | IP address geolocation, ASN lookups, reverse DNS, and abuse reputation. |
| `spectre url` | URL heuristic parsing, domain extraction, and threat intelligence lookups. |
| `spectre hash` | Cryptographic hash lookup against malware repositories (VirusTotal). |
| `spectre company` | Corporate footprint analysis and registered domains. |
| `spectre person` | Person-centric intelligence combining names, emails, and usernames. |
| `spectre threat` | Threat intelligence aggregator across configured security feeds. |
| `spectre wayback` | Historical snapshot search using the Wayback Machine API. |
| `spectre metadata` | File metadata extraction (EXIF, PDF metadata, creation dates). |
| `spectre network` | Authorized active TCP port reconnaissance (`--authorized` required). |
| `spectre auth` | Manage authenticated-public browser sessions (`login`, `status`, `logout`). |
| `spectre cache` | Inspect and purge HTTP result caches. |
| `spectre doctor` | Environment diagnostics and dependency health verification. |
| `spectre dashboard` | Launch the localhost web workstation (`spectre web`) *(Deprecated)*. |
| `spectre version` | Display installed version and build status. |

---

## Detailed Command Specifications

### 1. `spectre username`

Investigates a public username across the catalog, search intelligence, and public mentions.

```bash
spectre username TARGET [OPTIONS]
```

**Options:**
- `--alias TEXT`: Additional handles or nicknames associated with the target (can be specified multiple times).
- `--name TEXT`: Real or observed display name for context correlation.
- `--email TEXT`: Known or suspected seed email address.
- `--website TEXT`: Known personal website or portfolio domain.
- `--refresh`: Bypass cached HTTP results and force fresh live queries.
- `--no-report`: Skip writing generated report files to disk.

**Example:**
```bash
spectre username alice_osint \
  --alias alice-dev \
  --name "Alice Example" \
  --email alice@example.com \
  --website alice.example
```

---

### 2. `spectre investigate`

General-purpose entry point that automatically detects entity type (IP, Domain, Email, Username, Hash, URL) and dispatches the relevant analyzers.

```bash
spectre investigate TARGET [--type TYPE] [--refresh]
```

---

### 3. `spectre auth`

Manages operator sessions for authenticated-public collection.

- **Login to platform:**
  ```bash
  spectre auth login [instagram|facebook|threads|tiktok|x|twitch]
  ```
- **Check session status:**
  ```bash
  spectre auth status
  ```
- **Logout and destroy session state:**
  ```bash
  spectre auth logout [PLATFORM]
  ```

---

### 4. `spectre doctor`

Performs non-invasive installation checks and prints environment readiness.

```bash
spectre doctor [--json]
```

**Exit codes:**
- `0`: Environment ready (`READY` or `READY WITH OPTIONAL FEATURES MISSING`).
- `1`: Action required (e.g. database or report directories unwriteable).

---

### 5. `spectre cache`

Inspects or clears the local HTTP response cache (`data/cache/`).

- **View statistics:**
  ```bash
  spectre cache stats
  ```
- **Purge cache entries:**
  ```bash
  spectre cache clear
  ```

---

### 6. `spectre network` (Active Reconnaissance)

Performs TCP connect scanning against authorized infrastructure.

> [!CAUTION]
> Active network scanning sends direct TCP packets to target hosts. It is disabled by default and requires the `--authorized` flag plus an interactive confirmation.

```bash
spectre network TARGET --authorized
```
