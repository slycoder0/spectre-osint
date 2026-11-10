"""English catalog (the fallback language)."""

from __future__ import annotations

MESSAGES: dict[str, str] = {
    # --- global CLI --------------------------------------------------------------------
    "cli.lang_invalid": "Unsupported language: {value}. Use one of: {supported}.",
    "cli.banner.tagline": "passive-first, public sources only",
    # --- spectre config ---------------------------------------------------------------
    "cli.config.lang_saved": "Language saved: {language} ({path})",
    "cli.config.lang_env_override": (
        "Note: SPECTRE_LANG={value} is set in this environment and still takes precedence."
    ),
    # --- CLI errors (stderr): by error type, never the exception text ------------------
    "cli.error.label": "Error",
    "cli.error.ssrf": (
        "the target points to a private, local or reserved address. SPECTRE only queries "
        "public destinations (SSRF policy)."
    ),
    "cli.error.validation": (
        "the input is not a valid target for this command. Check the format; "
        "`spectre <command> --help` shows what is accepted."
    ),
    "cli.error.rate_limited": (
        "a remote service limited the requests (rate limit). Wait and try again; "
        "SPECTRE does not bypass limits."
    ),
    "cli.error.tls": (
        "the secure connection could not be verified (TLS certificate). SPECTRE does not "
        "skip certificate checks."
    ),
    "cli.error.network": (
        "a remote service could not be reached ({error}). Check your connection and try again."
    ),
    "cli.error.not_configured": "an optional provider is not configured. Run `spectre doctor`.",
    "cli.error.path_safety": (
        "a file or browser profile path was refused for safety (outside SPECTRE folders or "
        "a personal profile)."
    ),
    "cli.error.authorization": "active recon requires --authorized after confirming legal authorization.",
    "cli.error.auth": "the authenticated session could not be used ({error}). Run `spectre auth status`.",
    "cli.error.filesystem": (
        "filesystem error ({error}). Fix permissions or paths, then run `spectre doctor`."
    ),
    "cli.error.storage": (
        "cannot write SPECTRE data, logs or reports ({error}). Set SPECTRE_DATA_DIR / "
        "SPECTRE_REPORTS_DIR / SPECTRE_LOGS_DIR and run `spectre doctor`."
    ),
    "cli.error.database": (
        "the database is not writable ({error}). Set SPECTRE_DATA_DIR / "
        "SPECTRE_DATABASE_URL and run `spectre doctor`."
    ),
    "cli.error.reports_dir": (
        "the reports folder is not writable ({error}). Set SPECTRE_REPORTS_DIR and run "
        "`spectre doctor`."
    ),
    "cli.error.config_write": (
        "cannot save the preference ({error}). Check SPECTRE_CONFIG_FILE or the folder's "
        "permissions."
    ),
    "cli.error.generic": (
        "SPECTRE could not finish ({error}). Run `spectre doctor` or retry with --debug."
    ),
    # --- live progress (stderr, TTY only) ----------------------------------------------
    "progress.initializing": "Starting",
    "progress.catalog": "Checking public profiles",
    "progress.mentions": "Searching public mentions",
    "progress.search": "Searching the public web",
    "progress.discovery": "Analyzing leads",
    "progress.correlation": "Correlating evidence",
    "progress.scoring": "Scoring findings",
    "progress.report": "Writing report",
    "progress.collecting": "Collecting",
    "progress.normalizing": "Normalizing evidence",
    # --- spectre username (compact output) ---------------------------------------------
    "username.summary.one": "{target} — {count} profile found (sites checked: {checked})",
    "username.summary.other": "{target} — {count} profiles found (sites checked: {checked})",
    "username.likely": "(likely)",
    "username.names_header": "Names observed on each platform (not proof of the same person):",
    "username.unverified.one": "{count} not verified",
    "username.unverified.other": "{count} not verified",
    "username.bucket.blocked.one": "{count} blocked",
    "username.bucket.blocked.other": "{count} blocked",
    "username.bucket.login.one": "{count} needs login",
    "username.bucket.login.other": "{count} need login",
    "username.bucket.rate_limited.one": "{count} rate-limited",
    "username.bucket.rate_limited.other": "{count} rate-limited",
    "username.bucket.inconclusive.one": "{count} inconclusive",
    "username.bucket.inconclusive.other": "{count} inconclusive",
    "username.unverified_hint": "(--verbose lists them)",
    "username.report": "Full report: {path}",
    # --- spectre doctor -----------------------------------------------------------------
    "doctor.title": "SPECTRE DOCTOR {version}",
    "doctor.core_ok": "Core: OK (Python {python}, {database} database)",
    "doctor.security_ok": "Security: OK (SSRF policy enabled, secrets redacted)",
    "doctor.configured": "Configured: {items}",
    "doctor.session_item": "{platform} session",
    "doctor.optional_missing.one": (
        "{count} optional item not configured ({groups}) — `spectre doctor --all` lists it"
    ),
    "doctor.optional_missing.other": (
        "{count} optional items not configured ({groups}) — `spectre doctor --all` lists them"
    ),
    "doctor.overall": "Overall: {status}",
    "doctor.status.ready": "READY",
    "doctor.status.ready_optional": "READY WITH OPTIONAL FEATURES MISSING",
    "doctor.status.action_required": "ACTION REQUIRED",
    "doctor.state.ok": "OK",
    "doctor.state.optional": "OPTIONAL",
    "doctor.state.action": "ACTION",
    "doctor.state.info": "INFO",
    "doctor.group.core": "Core",
    "doctor.group.browser": "Browser",
    "doctor.group.search": "Search",
    "doctor.group.auth": "Authenticated public sessions",
    "doctor.group.providers": "API providers",
    "doctor.group.security": "Security",
    "doctor.short.core": "core",
    "doctor.short.browser": "browser",
    "doctor.short.search": "search",
    "doctor.short.auth": "sessions",
    "doctor.short.providers": "API keys",
    "doctor.short.security": "security",
    "doctor.label.package_import": "Package import",
    "doctor.label.database": "Database",
    "doctor.label.database_writable": "Database writable",
    "doctor.label.reports_directory": "Reports directory",
    "doctor.label.settings": "Settings",
    "doctor.label.secrets_redaction": "Secrets redaction",
    "doctor.label.ssrf_policy": "SSRF policy",
    "doctor.label.legacy_logs": "Legacy logs",
    "doctor.label.authenticated_sessions": "Authenticated sessions",
    "doctor.label.censys_secret": "Censys secret",
    "doctor.label.github_token": "GitHub token",
    "doctor.value.memory": "memory",
    "doctor.value.not_probed": "not probed",
    "doctor.value.detected": "detected",
    "doctor.value.missing": "missing",
    "doctor.value.inactive": "inactive",
    "doctor.value.listening": "listening",
    "doctor.value.configured": "configured",
    "doctor.value.configured_error": "configured (error)",
    "doctor.value.configured_offline": "configured (offline)",
    "doctor.value.invalid": "invalid",
    "doctor.value.configured_upper": "CONFIGURED",
    "doctor.value.not_configured_upper": "NOT CONFIGURED",
    "doctor.value.enabled": "enabled",
    "doctor.value.disabled": "disabled",
    "doctor.value.unreadable": "unreadable",
    "doctor.value.none": "none",
    "doctor.hint.python": "Python 3.12 or 3.13 is required.",
    "doctor.hint.data_dir": "SPECTRE_DATA_DIR must be writable.",
    "doctor.hint.database": "SPECTRE_DATA_DIR / SPECTRE_DATABASE_URL must be writable.",
    "doctor.hint.reports_dir": "SPECTRE_REPORTS_DIR must be writable.",
    "doctor.hint.chrome": "Optional. Needed for authenticated-public sessions.",
    "doctor.hint.cdp": "Doctor does not launch Chrome.",
    "doctor.hint.searxng_missing": "Set SEARXNG_URL=http://127.0.0.1:<port> for local search.",
    "doctor.hint.searxng_invalid": "SEARXNG_URL must be loopback http(s).",
    "doctor.hint.searxng_error": "Instance responded with a server error. Optional.",
    "doctor.hint.searxng_offline": "URL is set; instance did not respond. Optional.",
    "doctor.hint.settings": "Check .env syntax. Do not paste secrets into issues.",
    "doctor.hint.legacy_logs": (
        "Written by an earlier version; may contain target data. Delete it when you no longer "
        "need it. The default ./logs is relative to the folder spectre runs from, so other "
        "folders may have their own."
    ),
}
