# Troubleshooting & Diagnostic Guide

[English](troubleshooting.md) | [Português 🇧🇷](troubleshooting.pt-BR.md)

This guide covers common operational questions, platform rate-limiting behaviors, and troubleshooting steps for SPECTRE OSINT.

---

## 1. `spectre doctor` Statuses

### `READY WITH OPTIONAL FEATURES MISSING`
- **Is it an error?** No. SPECTRE is designed to function out-of-the-box with zero third-party API keys.
- **Why are providers `NOT CONFIGURED`?** Features like VirusTotal, Shodan, or loopback SearXNG are optional enhancements. When missing, those specific probes are gracefully skipped without halting investigations.

### `ACTION REQUIRED`
- **Reports or Data directory not writable:** Check user permissions on `./data` and `./reports`. Ensure the operating system user running SPECTRE has write permissions.
- **Bind address not on loopback:** By default, the web workstation binds strictly to `127.0.0.1`. If `SPECTRE_WEB_HOST` is configured to `0.0.0.0`, you must set `SPECTRE_ALLOW_PUBLIC_BIND=true` as an explicit acknowledgement of risk.

---

## 2. Platform Behaviors & Edge Filtering

### `LOGIN_REQUIRED`
- **Cause:** Platforms like Instagram, Facebook, or X actively wall public profiles behind login prompts.
- **Solution:** Use the [Authenticated Public](authenticated-public.md) collection mode:
  ```bash
  spectre auth login instagram
  ```

### `RATE_LIMITED` / `BLOCKED`
- **Cause:** The target platform returned HTTP `429 Too Many Requests` or a Cloudflare/WAF block page.
- **Behavior:** SPECTRE does not rotate residential proxies or attempt TLS spoofing. It records the factual status and moves on to the next source. Wait a few minutes before querying the same platform again.

### `PROVIDER_UNAVAILABLE` (Circuit Breaker)
- **Cause:** Repeated network timeouts or DNS resolution failures on a specific remote provider (e.g. `html.duckduckgo.com`).
- **Behavior:** SPECTRE trips a host-level circuit breaker to fail-fast on subsequent queries to that host during the same investigation run, preventing wasted timeouts.

---

## 3. Platform Specifics: Windows & WSL2

- **Windows Native vs. WSL2:** SPECTRE is verified on native Windows 11 and Ubuntu/WSL2.
- **Chrome CDP Interop:** On WSL2, SPECTRE can automatically bridge to Google Chrome installed on the Windows host using PowerShell `Start-Process`. On native Windows, it launches the installed `chrome.exe` directly.

---

## 4. Cache Management

If you suspect stale responses from previous queries:

```bash
# View cache metrics
spectre cache stats

# Purge cache
spectre cache clear

# Or force fresh queries on a specific investigation
spectre username alice_osint --refresh
```
