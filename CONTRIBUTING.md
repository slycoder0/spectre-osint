# Contributing

SPECTRE is passive-first public OSINT. Patches that bypass access controls,
CAPTCHAs, or private content will be rejected.

Contributors: read [Architecture Guide](docs/technical/architecture.md) and [Testing Guide](docs/technical/testing.md) before changing code.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
spectre doctor
```

## Required checks

```bash
pytest
ruff check spectre_osint tests
mypy spectre_osint
pip check
```

## Rules

- Do not change scoring weights, identity thresholds, or username classifiers
  silently. If a bug forces a change, explain it in the commit and add a
  regression test.
- Add provenance for observed fields. Operator input is not observed evidence.
- HTTP 200 alone is never `CONFIRMED`.
- Do not implement CAPTCHA solving, TLS fingerprint spoofing, proxy rotation,
  stealth browsers, or authenticated scraping of private/DM content.
- Fixtures must be synthetic (`alice_osint`, `Alice Example`). Tests must not
  depend on live personal accounts.
- Never commit `.env`, cookies, session files, Chrome profiles, or real reports.

## CLI notes

- `spectre doctor` diagnoses the install. It must not start investigations.
- `spectre web` starts the legacy dashboard (`spectre dashboard` is an alias; deprecated: scheduled for removal in 0.1.0b2).
