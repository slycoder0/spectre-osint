"""Local-only GUI translations. English default. No network, no tracking."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from starlette.requests import Request

I18N_DIR = Path(__file__).resolve().parent / "i18n"
SUPPORTED = ("en", "pt-BR")
DEFAULT_LANG = "en"
DEFAULT_THEME = "dark"
LANG_COOKIE = "spectre_lang"
THEME_COOKIE = "spectre_theme"


def normalize_lang(value: str | None) -> str:
    raw = (value or "").strip()
    lowered = raw.lower().replace("_", "-")
    if lowered in {"pt", "pt-br", "pt-br-br"}:
        return "pt-BR"
    return "en"


def normalize_theme(value: str | None) -> str:
    return "light" if (value or "").strip().lower() == "light" else "dark"


def resolve_lang(request: Request) -> str:
    return normalize_lang(request.cookies.get(LANG_COOKIE))


def resolve_theme(request: Request) -> str:
    return normalize_theme(request.cookies.get(THEME_COOKIE))


@lru_cache(maxsize=4)
def _load(lang: str) -> dict[str, Any]:
    name = "pt-BR.json" if lang == "pt-BR" else "en.json"
    path = I18N_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def _lookup(tree: dict[str, Any], key: str) -> Any:
    cur: Any = tree
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class Translator:
    def __init__(self, lang: str) -> None:
        self.lang = normalize_lang(lang)
        self._primary = _load(self.lang)
        self._fallback = _load(DEFAULT_LANG)

    def __call__(self, key: str, default: str | None = None) -> str:
        value = _lookup(self._primary, key)
        if value is None:
            value = _lookup(self._fallback, key)
        if value is None:
            return default if default is not None else key
        if isinstance(value, dict):
            hint = value.get("hint")
            return str(hint) if hint is not None else key
        return str(value)

    def html_lang(self) -> str:
        return "pt-BR" if self.lang == "pt-BR" else "en"


def translator(lang: str) -> Translator:
    return Translator(lang)
