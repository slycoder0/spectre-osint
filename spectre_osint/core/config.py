"""Runtime configuration loaded from environment / .env."""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_DIR.parent
BUNDLED_DATA_DIR = PACKAGE_DIR / "data"

_KNOWN_PLACEHOLDERS = frozenset(
    {
        "placeholder",
        "your_api_key_here",
        "your_token_here",
        "your_key_here",
        "your_api_key",
        "your_token",
        "your_api_id",
        "your_api_secret",
        "changeme",
        "change_me",
        "none",
        "null",
        "undefined",
        "xxx",
        "xxxx",
        "todo",
    }
)


def _is_valid_credential_string(raw: str) -> bool:
    """Check if a string represents a valid, non-placeholder, ASCII credential."""
    if not raw:
        return False
    stripped = raw.strip()
    if not stripped:
        return False
    if stripped.startswith("#"):
        return False
    if stripped.startswith("<") and stripped.endswith(">") and len(stripped) > 2:
        return False
    if stripped.lower() in _KNOWN_PLACEHOLDERS:
        return False
    try:
        raw_bytes = stripped.encode("ascii")
    except UnicodeEncodeError:
        return False
    if any(b < 32 or b == 127 for b in raw_bytes):
        return False
    return True


def normalize_secret(v: Any) -> SecretStr | None:
    if v is None:
        return None
    if isinstance(v, SecretStr):
        raw = v.get_secret_value()
    else:
        raw = str(v)
    if not _is_valid_credential_string(raw):
        return None
    return SecretStr(raw.strip())


def normalize_optional_str(v: Any) -> str | None:
    if v is None:
        return None
    raw = str(v)
    if not _is_valid_credential_string(raw):
        return None
    return raw.strip()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    data_dir: Path = Field(default=Path("./data"), alias="SPECTRE_DATA_DIR")
    reports_dir: Path = Field(default=Path("./reports"), alias="SPECTRE_REPORTS_DIR")
    logs_dir: Path = Field(default=Path("./logs"), alias="SPECTRE_LOGS_DIR")
    log_level: str = Field(default="INFO", alias="SPECTRE_LOG_LEVEL")
    database_url: str = Field(default="", alias="SPECTRE_DATABASE_URL")
    http_timeout: float = Field(default=20.0, alias="SPECTRE_HTTP_TIMEOUT")
    max_concurrency: int = Field(default=8, alias="SPECTRE_MAX_CONCURRENCY")
    http_max_retries: int = Field(default=3, alias="SPECTRE_HTTP_MAX_RETRIES")
    http_retry_budget: float = Field(default=20.0, alias="SPECTRE_HTTP_RETRY_BUDGET")
    http_max_backoff: float = Field(default=30.0, alias="SPECTRE_HTTP_MAX_BACKOFF")
    http_circuit_failures: int = Field(default=3, alias="SPECTRE_HTTP_CIRCUIT_FAILURES")
    user_agent: str = Field(
        default="SPECTRE-OSINT/0.1-alpha (+passive-osint)",
        alias="SPECTRE_USER_AGENT",
    )
    ssrf_enabled: bool = Field(default=True, alias="SPECTRE_SSRF_ENABLED")
    allow_private_targets: bool = Field(default=False, alias="SPECTRE_ALLOW_PRIVATE_TARGETS")
    allow_public_bind: bool = Field(default=False, alias="SPECTRE_ALLOW_PUBLIC_BIND")
    web_host: str = Field(default="127.0.0.1", alias="SPECTRE_WEB_HOST")
    pivot_budget: int = Field(default=8, alias="SPECTRE_PIVOT_BUDGET")
    searxng_url: str | None = Field(default=None, alias="SEARXNG_URL")
    search_query_budget: int = Field(default=12, alias="SPECTRE_SEARCH_QUERY_BUDGET")
    search_max_pivots: int = Field(default=25, alias="SPECTRE_SEARCH_MAX_PIVOTS")
    search_max_depth: int = Field(default=2, alias="SPECTRE_SEARCH_MAX_DEPTH")

    cache_dns_ttl: int = Field(default=600, alias="SPECTRE_CACHE_DNS_TTL")
    cache_rdap_ttl: int = Field(default=86400, alias="SPECTRE_CACHE_RDAP_TTL")
    cache_vt_ttl: int = Field(default=3600, alias="SPECTRE_CACHE_VT_TTL")
    cache_crtsh_ttl: int = Field(default=21600, alias="SPECTRE_CACHE_CRTSH_TTL")
    cache_default_ttl: int = Field(default=1800, alias="SPECTRE_CACHE_DEFAULT_TTL")
    cache_username_ttl: int = Field(default=21600, alias="SPECTRE_CACHE_USERNAME_TTL")
    cache_wayback_ttl: int = Field(default=21600, alias="SPECTRE_CACHE_WAYBACK_TTL")
    cache_health_ttl: int = Field(default=900, alias="SPECTRE_CACHE_HEALTH_TTL")
    auth_dir: Path | None = Field(default=None, alias="SPECTRE_AUTH_DIR")
    browser_profiles_dir: Path | None = Field(default=None, alias="SPECTRE_BROWSER_PROFILES_DIR")
    chrome_path: Path | None = Field(default=None, alias="SPECTRE_CHROME_PATH")
    chrome_profiles_dir: Path | None = Field(default=None, alias="SPECTRE_CHROME_PROFILES_DIR")
    windows_userprofile: Path | None = Field(default=None, alias="SPECTRE_WINDOWS_USERPROFILE")
    browser_backend: str = Field(default="playwright", alias="SPECTRE_BROWSER_BACKEND")
    browser_visible: bool = Field(default=False, alias="SPECTRE_BROWSER_VISIBLE")
    keyring_enabled: bool = Field(default=True, alias="SPECTRE_KEYRING")

    virustotal_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    censys_api_id: SecretStr | None = None
    censys_api_secret: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    hibp_api_key: SecretStr | None = None
    ipinfo_token: SecretStr | None = None
    greynoise_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    google_api_key: SecretStr | None = None
    google_cse_id: str | None = None

    openai_api_key: SecretStr | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: SecretStr | None = None
    openrouter_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"
    llm_enabled: bool = False

    @field_validator(
        "virustotal_api_key",
        "shodan_api_key",
        "censys_api_id",
        "censys_api_secret",
        "urlscan_api_key",
        "abuseipdb_api_key",
        "hibp_api_key",
        "ipinfo_token",
        "greynoise_api_key",
        "github_token",
        "otx_api_key",
        "google_api_key",
        "openai_api_key",
        "anthropic_api_key",
        "openrouter_api_key",
        "gemini_api_key",
        mode="before",
    )
    @classmethod
    def _validate_secrets(cls, v: Any) -> SecretStr | None:
        return normalize_secret(v)

    @field_validator("google_cse_id", mode="before")
    @classmethod
    def _validate_google_cse_id(cls, v: Any) -> str | None:
        return normalize_optional_str(v)

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "cache").mkdir(parents=True, exist_ok=True)

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        db_path = (self.data_dir / "spectre.db").resolve()
        return f"sqlite:///{db_path}"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def resolved_auth_dir(self) -> Path:
        if self.auth_dir:
            return Path(self.auth_dir).expanduser()
        return default_auth_dir()

    @property
    def resolved_browser_profiles_dir(self) -> Path:
        if self.browser_profiles_dir:
            return Path(self.browser_profiles_dir).expanduser()
        return default_browser_profiles_dir()

    def secret_present(self, name: str) -> bool:
        value = getattr(self, name, None)
        if value is None:
            return False
        if isinstance(value, SecretStr):
            return _is_valid_credential_string(value.get_secret_value())
        return _is_valid_credential_string(str(value))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_dirs()
    return settings


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


def default_auth_dir() -> Path:
    """Operator session store. Never inside the git repository."""
    override = os.environ.get("SPECTRE_AUTH_DIR")
    if override:
        return Path(override).expanduser()
    return _spectre_data_home() / "auth"


def default_browser_profiles_dir() -> Path:
    """SPECTRE-owned Chromium profiles. Never the operator's real Chrome/Edge."""
    override = os.environ.get("SPECTRE_BROWSER_PROFILES_DIR")
    if override:
        return Path(override).expanduser()
    return _spectre_data_home() / "browser-profiles"


def _spectre_data_home() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "spectre"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "spectre"
    return Path.home() / ".local" / "share" / "spectre"
