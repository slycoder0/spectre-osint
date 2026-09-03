# Changelog

All notable changes to SPECTRE OSINT are documented here.

The format is based on Keep a Changelog.

## [Unreleased]

### Changed
- **Site Catalog identity is now explicit (B2-02B):** all 57 production entries in
  `spectre_osint/data/sites.yaml` declare a stable `slug`, and loading the bundled
  production catalog rejects an entry that omits or blanks it instead of deriving one
  from the display name;
- display names are presentation labels only: renaming a provider no longer moves
  its stable identifier;
- production catalog validation inspects the *declared* slug before model
  normalization, so leading/trailing whitespace (`" github "`) and uppercase
  (`GitHub`) are rejected rather than silently rewritten, alongside missing, blank,
  malformed (outside `^[a-z0-9_]+$`) and duplicate values — each with a diagnostic
  naming the site and field;
- every declared slug is the identifier the entry already resolved to, so no
  effective provider identifier changed and no provider behavior changed;
- `slugify_name()` is retained as a compatibility fallback for custom and legacy
  definitions, reachable through `SiteCatalog.from_dict()`,
  `SiteCatalog.from_yaml_file()`, `SiteDefinition.model_validate()`, and
  `load_catalog()` / `load_sites()` for any path that is not the bundled catalog;
- `load_catalog()` and `load_sites()` accept `require_explicit_slug`: the default
  resolves the contract from the target — strict for the bundled production catalog,
  lenient for a custom path, preserving pre-B2-02B behavior for existing
  `load_sites(custom_path)` callers — and `True` / `False` state it deliberately;
- the in-memory catalog cache is keyed by path *and* validation mode, so a
  leniently loaded catalog can never be served to a strict caller.

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
