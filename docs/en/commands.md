# CLI Commands Reference

Complete list of the commands exposed by the `spectre` entry point. Options are listed only where they were verified against the Typer definitions; run `spectre <command> --help` for the authoritative signature.

---

## Global Options

| Option | Effect |
| :--- | :--- |
| `--version` | Prints the installed version and exits. |
| `--no-banner` | Skips the ASCII banner. |
| `--compact` | Summary-oriented output. |
| `--verbose` | Expands result presentation (entity table, extra detail column). It does not change the log level. |
| `--help` | Shows help for the CLI or for a specific command. |

---

## Environment & Diagnostics

| Command | Description |
| :--- | :--- |
| `spectre version` | Prints the installed version (equivalent to the global `--version`). |
| `spectre doctor [--json]` | Inspects install, database, browser, sessions and provider configuration. Never starts an investigation and never prints secrets. Exits `1` only when the overall status is `ACTION REQUIRED`. |

---

## Indicator Investigation

| Command | Description |
| :--- | :--- |
| `spectre username <handle>` | Public profile sweep across the Site Catalog with metadata extraction. Accepts `--alias`, `--name`, `--email`, `--website`, `--auto-pivot`, `--depth`, `--case` and `--refresh` (ignores the result cache). |
| `spectre email <email>` | Format validation, DNS/MX records and public footprint. |
| `spectre domain <domain>` | DNS, RDAP registration, Certificate Transparency and host fingerprinting. Accepts `--auto-pivot` and `--depth`. |
| `spectre ip <ip>` | IPv4/IPv6 intelligence: network allocation and reputation history. |
| `spectre url <url>` | URL analysis with explainable heuristic risk. |
| `spectre hash <hash>` | Public reputation for MD5/SHA-1/SHA-256/SHA-512 hashes. Malware is never downloaded. |
| `spectre company <name>` | Public organization footprint via the GitHub organization profile. No employee scraping. |
| `spectre person <name>` | Uses the name as investigative context; it does **not** run a broad web-mention search on the name alone. Accepts `--username` (catalog sweep) and `--email` (email/MX analysis). Without `--username`, the GitHub lookup falls back to treating the given name as an exact login. Similar profiles stay `possible_match` and are never promoted to a confirmed identity. |
| `spectre metadata <path>` | Extracts metadata from an operator-supplied local file. Strictly local; no macros or active content are executed. |
| `spectre threat <indicator>` | Auto-detects the indicator type (IP, domain, URL or hash) and runs the matching investigation pipeline. There is no separate threat-intel-only pipeline. |
| `spectre wayback <domain>` | Normalizes the target as a domain and runs the domain pipeline, which includes the Wayback/CDX query among the other collectors. |

---

## Full Investigation, Cases & Reports

| Command | Description |
| :--- | :--- |
| `spectre investigate <target>` | Full unified pipeline: target-type detection, catalog sweep, public mention search, indicator extraction, conservative identity correlation and HTML dossier. Accepts the same leads as `spectre username` plus `--auto-pivot`, `--depth` and `--case`. |
| `spectre search <query>` | Public search helper backed by Google Custom Search. Requires both `GOOGLE_API_KEY` and `GOOGLE_CSE_ID`; without them the command returns `NOT_CONFIGURED`. Results are public search links, not identity confirmation. |
| `spectre case create <name> [description]` | Creates a case and makes it active. If the name already exists, the existing case is returned unchanged and is **not** re-activated. |
| `spectre case select <name>` | Makes an existing case active; fails if the name is unknown. |
| `spectre case list` | Lists local cases, marking the active one. |
| `spectre case runs <name>` | Lists the runs recorded for a case. |
| `spectre case rollback <run_id>` | Deletes the findings, evidence and relationships written by one run. It does **not** undo report files already on disk. |
| `spectre report [CASE] [--format]` | Regenerates artifacts from the latest completed run. The case is a **positional** argument (there is no `--case` here); omitting it uses the active case. `--format` accepts `html`, `markdown`, `json`, `csv`, `graphml` or `all`. |

`--case` exists only on `username` and `investigate`. It selects the named case when it exists and creates it when it does not; without it, every run creates a new case with a generated unique name.

---

## Authenticated Public Sessions

Supported platforms: `instagram`, `facebook`, `threads`, `tiktok`, `x`, `twitch`. SPECTRE never receives or stores passwords — login is performed manually by the operator in a visible browser window.

| Command | Description |
| :--- | :--- |
| `spectre auth status` | Session status for every supported platform. Cookies are never printed. |
| `spectre auth list` | Same output as `status`. |
| `spectre auth login <platform>` | Opens a visible browser for manual login. Accepts `--profile` (session-registry label, default `osint-research`), `--keep-open`, `--timeout` (seconds, default `300`, range `30`–`1800`), `--browser` (`auto`, `playwright` or `chrome`) and `--attach` (reuse an already-running SPECTRE Chrome CDP endpoint; never launches the browser). |
| `spectre auth verify <platform>` | Checks whether a saved session is still valid. Never logs in automatically. |
| `spectre auth logout <platform>` | Removes the local session record and wipes both dedicated SPECTRE browser profiles (Chromium/Playwright and Chrome CDP). Remote accounts and the personal browser are untouched. |
| `spectre auth clear <platform>` | Alias for `logout`, with the same effect. |

---

## Providers & Cache

| Command | Description |
| :--- | :--- |
| `spectre providers [--probe] [--name <provider>]` | Lists the providers registered in the runtime provider registry with configuration and health state. `--probe` performs a cheap live check and consumes quota. |
| `spectre cache status` | Shows the local OSINT **result** cache. |
| `spectre cache clear [--provider <name>]` | Clears result-cache entries. This does **not** touch the separate HTTP response cache used by the HTTP client, which keeps serving cached responses within its own TTL. |

---

## Active Reconnaissance (opt-in)

| Command | Description |
| :--- | :--- |
| `spectre network <host> --authorized` | The only **active** command. Disabled by default: it requires the `--authorized` flag **and** an interactive terminal confirmation. Performs a TCP connect scan over a small fixed port list with an optional short banner read. It does not exploit vulnerabilities, brute-force credentials, mass-scan or evade defenses. |

---

## Legacy Web Interface (removed)

`spectre web` and `spectre dashboard` were **removed** in the 0.1.0b2 development
milestone; invoking either fails as an unknown command. SPECTRE is CLI-first: run
the investigation commands above and use `spectre report` for standalone
single-file report artifacts.
