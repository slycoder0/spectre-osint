"""Message catalog and language selection for terminal output (B2-06).

Two languages ship: English (`en`, the fallback) and Brazilian Portuguese (`pt-BR`).
Catalogs are plain Python dicts in `spectre_osint/core/locales/`; there is no gettext,
no compiled `.mo` file and no extra dependency.

`t(key, **values)` formats one message in the active language. A key missing from the
active catalog falls back to English, and a key missing everywhere is returned as-is, so
a translation gap degrades to readable text instead of a crash. `tn(key, count)` picks
`key.one` or `key.other`.

The active language is resolved in a fixed order, first match wins:

1. the global `--lang` flag (an unsupported value is an error);
2. the `SPECTRE_LANG` environment variable;
3. the persisted user config (`{"language": ...}` in `config_file_path()`);
4. the system locale;
5. English.

Sources 2-4 may hold anything a person typed; an unsupported value there is skipped,
never fatal. Only reports and terminal text are translated — data, status codes and the
JSON contract stay language-neutral.
"""

from __future__ import annotations

import json
import locale
import os
from collections.abc import Callable, Mapping
from pathlib import Path

from spectre_osint.core.config import default_config_file
from spectre_osint.core.locales import en, pt_br

DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES: tuple[str, ...] = ("en", "pt-BR")
CATALOGS: dict[str, Mapping[str, str]] = {"en": en.MESSAGES, "pt-BR": pt_br.MESSAGES}

LANG_ENV = "SPECTRE_LANG"
_LOCALE_ENV = ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")
_CONFIG_KEY = "language"

_active: str | None = None


def normalize_language(value: str | None) -> str | None:
    """Map a flag, env value or locale name to a supported language, or None.

    Accepts the spellings people and systems actually produce: `pt`, `pt-BR`, `pt_br`,
    `pt_BR.UTF-8`, Windows' `Portuguese_Brazil`, `en_US`, `English_United States`. Any
    Portuguese variant maps to `pt-BR` (the only Portuguese catalog); `C`/`POSIX` and
    anything unknown map to None.
    """
    if not value:
        return None
    text = str(value).strip().lower().replace("_", "-")
    text = text.split(".", 1)[0].split("@", 1)[0]
    if text in {"", "c", "posix"}:
        return None
    if text == "pt" or text.startswith("pt-") or text.startswith("portuguese"):
        return "pt-BR"
    if text == "en" or text.startswith("en-") or text.startswith("english"):
        return "en"
    return None


def system_language(
    *,
    environ: Mapping[str, str] | None = None,
    getlocale: Callable[[], tuple[str | None, str | None]] | None = None,
) -> str | None:
    """The language the operating system asks for, when it is one SPECTRE ships.

    POSIX variables are read first, in their precedence order (`LANGUAGE` may hold a
    colon-separated list); an unset, `C` or unsupported value moves on to the next. On
    Windows those are normally absent and `locale.getlocale()` answers with names such
    as `Portuguese_Brazil`.
    """
    env = os.environ if environ is None else environ
    for name in _LOCALE_ENV:
        for part in str(env.get(name) or "").split(":"):
            found = normalize_language(part)
            if found:
                return found
    reader = getlocale or locale.getlocale
    try:
        code = reader()[0]
    except (ValueError, TypeError, IndexError):
        return None
    return normalize_language(code)


def config_file_path(environ: Mapping[str, str] | None = None) -> Path:
    """Where the persisted user preferences live. `SPECTRE_CONFIG_FILE` overrides."""
    return default_config_file(environ)


def _read_config(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def load_saved_language(path: Path | None = None) -> str | None:
    """The persisted language, or None when absent, unreadable or unsupported."""
    raw = _read_config(path or config_file_path()).get(_CONFIG_KEY)
    return normalize_language(raw) if isinstance(raw, str) else None


def save_language(language: str, path: Path | None = None) -> Path:
    """Persist the preferred language, keeping any other config keys. Returns the path."""
    normalized = normalize_language(language)
    if normalized is None:
        raise ValueError(f"unsupported language: {language!r}")
    target = path or config_file_path()
    payload = _read_config(target)
    payload[_CONFIG_KEY] = normalized
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def resolve_language(
    flag: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    config_path: Path | None = None,
    system: Callable[[], str | None] | None = None,
) -> str:
    """Apply the documented resolution order. Raises ValueError for a bad `--lang`."""
    if flag is not None and flag.strip():
        chosen = normalize_language(flag)
        if chosen is None:
            raise ValueError(f"unsupported language: {flag!r}")
        return chosen
    env = os.environ if environ is None else environ
    from_env = normalize_language(env.get(LANG_ENV))
    if from_env:
        return from_env
    saved = load_saved_language(config_path or config_file_path(env))
    if saved:
        return saved
    detected = (system or (lambda: system_language(environ=env)))()
    return normalize_language(detected) or DEFAULT_LANGUAGE


def set_language(language: str | None) -> None:
    """Pin the active language, or pass None to resolve it lazily on next use."""
    global _active
    _active = normalize_language(language) if language is not None else None


def get_language() -> str:
    """The active language, resolving (and caching) it the first time it is needed."""
    global _active
    if _active is None:
        _active = resolve_language()
    return _active


def _template(key: str) -> str:
    found = CATALOGS.get(get_language(), {}).get(key)
    if found is None:
        found = CATALOGS.get(DEFAULT_LANGUAGE, {}).get(key)
    return key if found is None else found


def has_message(key: str) -> bool:
    return key in CATALOGS.get(DEFAULT_LANGUAGE, {})


def t(key: str, **values: object) -> str:
    """One message in the active language. Values are inserted, never re-parsed."""
    template = _template(key)
    if not values:
        return template
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


def tn(key: str, count: int, **values: object) -> str:
    """Plural-aware `t()`: `key.one` when count is 1, `key.other` otherwise."""
    suffix = "one" if count == 1 else "other"
    return t(f"{key}.{suffix}", count=count, **values)
