# Changelog

All notable changes to SPECTRE OSINT are documented here.

The format is based on Keep a Changelog.

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
- `0.1.0b1` validated on CI (Python 3.12 / 3.13) and Windows native (ready to tag).
