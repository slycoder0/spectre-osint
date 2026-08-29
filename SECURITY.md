# Security policy

SPECTRE OSINT is a **localhost, single-operator** workstation. It is not hardened
for exposure to untrusted networks.

## Reporting a vulnerability

Do **not** open a public issue that includes exploit details, cookies, session
files, API keys, or unsanitized investigation reports.

If the repository enables GitHub Security Advisories, use that private channel.

Do not invent or guess a security email. If advisories are unavailable, describe
the class of issue without payloads until a maintainer provides a private path.

## Do not publish

- API keys, tokens, `Authorization` headers
- cookies, `storage_state.json`, Playwright/Chrome session files
- SPECTRE Chrome profile directories
- unsanitized HTML/JSON reports of real people
- personal data that is not required to reproduce a bug

Paste `spectre doctor --json` instead of environment dumps. Doctor is designed
to say `CONFIGURED` rather than print secrets.

## Model

- Dashboard bind default is `127.0.0.1`.
- `AUTHENTICATED_PUBLIC` means the operator logged in to view **public** pages
  in a SPECTRE-owned browser profile. It is not private-message access and not
  a bypass of platform controls.
- SPECTRE does not solve CAPTCHAs, does not hide automation, and does not
  store passwords.
- SSRF policy blocks loopback/private/metadata targets except explicitly
  documented local helpers (loopback SearXNG).

## Supported versions

Beta (`0.1.0b1`) is the current tree. There is no stable release yet. Fixes
land on `main` as local/development commits until a beta is tagged.
