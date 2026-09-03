# Changelog

All notable changes to SPECTRE OSINT are documented here.

The format is based on Keep a Changelog.

## [Unreleased]

### Removed
- **BREAKING:** the deprecated `spectre web` and `spectre dashboard` commands were
  removed; invoking either now fails as an unknown command with a non-zero exit;
- the legacy web runtime `spectre_osint/web/` was deleted (FastAPI application,
  Jinja2 templates, static assets, bundled fonts, i18n catalogs, in-memory job
  runner and the dashboard graph view);
- dashboard-only configuration retired with no compatibility aliases:
  `SPECTRE_WEB_HOST` / `Settings.web_host`, `SPECTRE_ALLOW_PUBLIC_BIND` /
  `Settings.allow_public_bind`, and the `spectre doctor` "Bind address" check;
- web-only runtime dependencies dropped: `fastapi`, `starlette`,
  `uvicorn[standard]`, `python-multipart`;
- container plumbing that only served the dashboard removed (`EXPOSE 8000`, the
  published loopback port and the `command: ["web", ...]` compose override).

### Documentation
- documentation consolidated into a single MkDocs Material site (`mkdocs.yml`), with
  PT-BR as the canonical language and the previous paths kept as redirect stubs;
- CLI reference, configuration reference and evidence/provenance semantics aligned
  with the current runtime behavior;
- `docs` optional-dependency group added (`mkdocs`, `mkdocs-material`,
  `pymdown-extensions`) and the generated `site/` directory ignored by git;
- command, configuration, architecture, contributing and security docs updated for
  the post-removal state.

### Notes
- SPECTRE is CLI-first: investigations run from the CLI and are reviewed through
  the standalone single-file HTML/JSON/Markdown/CSV/GraphML report artifacts;
- `SPECTRE_SSRF_ENABLED` and `SPECTRE_ALLOW_PRIVATE_TARGETS` are unchanged — they
  govern outbound request safety, not a listening socket;
- evidence, scoring, correlation, provider and pipeline semantics are unchanged;
- `docs/technical/legacy-web.md` is kept as the historical removal record.

## [0.1.0b1] - 2026-08-27

### Reliability / resilience
- deterministic TLS verification failures no longer consume retries;
- repeated host-level outages fail fast within the same investigation;
- new investigations start with fresh host resilience state.

### Evidence quality
- generic platform branding/marketing titles are rejected as identity evidence;
- generic pages no longer become LIKELY from weak boilerplate-only signals.

### Progress / workstation
- factual structured investigation progress events;
- CLI displays real investigation phases;
- Web collecting screen displays live factual phases and degraded providers;
- no fabricated percentages for unknown workloads.

### Platform compatibility
- Windows/POSIX tests made portable without weakening POSIX assertions;
- WSL -> Windows Chrome path normalization improved;
- native Windows suite reached 475 passed / 0 failed.

### Documentation
- README redesigned as compact public landing page;
- full EN and PT-BR documentation paths;
- deeper documentation split into focused clickable guides.

### Release hardening
- dependency/security preflight passed;
- artifact/secret audit passed;
- doctor reports ready with optional features missing.

### Notes
- `0.1.0b1` validated on CI (Python 3.12 / 3.13) and Windows native; tagged as the
  annotated tag `0.1.0b1` and pushed to `origin`.
