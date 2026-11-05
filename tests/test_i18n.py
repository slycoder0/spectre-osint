"""i18n base (B2-06): PT-BR / EN catalogs, `t()`, and language resolution order.

Resolution order is fixed: --lang flag, then SPECTRE_LANG, then the persisted config,
then the system locale, then English. Every source but the explicit flag is allowed to
be wrong (a typo in an env var or a hand-edited config) without breaking the CLI; it is
simply skipped.
"""

from __future__ import annotations

import json
import re
import string
from pathlib import Path

import pytest

from spectre_osint.core import i18n
from spectre_osint.core.i18n import (
    CATALOGS,
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    load_saved_language,
    normalize_language,
    resolve_language,
    save_language,
    set_language,
    system_language,
    t,
    tn,
)

PACKAGE = Path(__file__).resolve().parent.parent / "spectre_osint"


def _placeholders(template: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(template) if name}


# --- catalog parity -------------------------------------------------------------------


def test_supported_languages_are_english_and_brazilian_portuguese() -> None:
    assert SUPPORTED_LANGUAGES == ("en", "pt-BR")
    assert DEFAULT_LANGUAGE == "en"
    assert set(CATALOGS) == set(SUPPORTED_LANGUAGES)


def test_pt_br_and_en_have_exactly_the_same_keys() -> None:
    en = set(CATALOGS["en"])
    pt = set(CATALOGS["pt-BR"])
    assert en, "the English catalog must not be empty"
    assert sorted(en - pt) == [], "keys missing in pt-BR"
    assert sorted(pt - en) == [], "keys missing in en"


def test_pt_br_and_en_use_the_same_placeholders_per_key() -> None:
    mismatched = {
        key: (sorted(_placeholders(CATALOGS["en"][key])), sorted(_placeholders(CATALOGS["pt-BR"][key])))
        for key in CATALOGS["en"]
        if _placeholders(CATALOGS["en"][key]) != _placeholders(CATALOGS["pt-BR"].get(key, ""))
    }
    assert mismatched == {}


def test_catalog_values_are_non_empty_strings() -> None:
    for lang, catalog in CATALOGS.items():
        for key, value in catalog.items():
            assert isinstance(value, str) and value.strip(), f"{lang}:{key} is empty"


def test_plural_keys_come_in_one_and_other_pairs() -> None:
    for catalog in CATALOGS.values():
        for key in catalog:
            if key.endswith(".one"):
                assert key[: -len(".one")] + ".other" in catalog, key
            if key.endswith(".other"):
                assert key[: -len(".other")] + ".one" in catalog, key


_KEY_LITERAL = re.compile(r"""["']((?:cli|doctor|username|progress)\.[a-z0-9_]+(?:\.[a-z0-9_]+)*)["']""")


def test_every_catalog_key_referenced_in_code_exists() -> None:
    """A typo in a key would silently print the key itself; catch it here instead."""
    catalog = CATALOGS["en"]
    missing: list[str] = []
    for path in PACKAGE.rglob("*.py"):
        if "locales" in path.parts:
            continue
        for key in _KEY_LITERAL.findall(path.read_text(encoding="utf-8")):
            if key in catalog:
                continue
            if f"{key}.one" in catalog and f"{key}.other" in catalog:
                continue
            if any(existing.startswith(key + ".") for existing in catalog):
                continue  # a prefix used to build keys from a closed set
            missing.append(f"{path.name}: {key}")
    assert missing == []


# --- t() / tn() -------------------------------------------------------------------------


def test_t_formats_placeholders_in_the_active_language() -> None:
    set_language("en")
    assert t("username.report", path="r.html") == "Full report: r.html"
    set_language("pt-BR")
    assert t("username.report", path="r.html") == "Relatório completo: r.html"


def test_t_falls_back_to_english_then_to_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    patched = {"en": {"x.only_en": "English only"}, "pt-BR": {}}
    monkeypatch.setattr(i18n, "CATALOGS", patched)
    set_language("pt-BR")
    assert t("x.only_en") == "English only"
    assert t("x.unknown") == "x.unknown"


def test_t_never_raises_on_a_missing_placeholder_value() -> None:
    set_language("en")
    assert "{path}" in t("username.report")


def test_t_does_not_interpret_values_as_format_strings() -> None:
    set_language("en")
    assert t("username.report", path="{0}{x}") == "Full report: {0}{x}"


def test_tn_picks_singular_and_plural() -> None:
    set_language("pt-BR")
    assert tn("username.unverified", 1) == "1 não verificado"
    assert tn("username.unverified", 0) == "0 não verificados"
    assert tn("username.unverified", 7) == "7 não verificados"
    set_language("en")
    assert tn("username.unverified", 1) == "1 not verified"
    assert tn("username.unverified", 3) == "3 not verified"


# --- normalization ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("en", "en"),
        ("EN", "en"),
        ("en_US", "en"),
        ("en-GB.UTF-8", "en"),
        ("English_United States", "en"),
        ("pt", "pt-BR"),
        ("pt-BR", "pt-BR"),
        ("pt_br", "pt-BR"),
        ("pt_BR.UTF-8", "pt-BR"),
        ("pt_PT", "pt-BR"),
        ("Portuguese_Brazil", "pt-BR"),
        ("C", None),
        ("POSIX", None),
        ("C.UTF-8", None),
        ("", None),
        (None, None),
        ("fr_FR", None),
        ("klingon", None),
    ],
)
def test_normalize_language(raw: str | None, expected: str | None) -> None:
    assert normalize_language(raw) == expected


# --- system locale ----------------------------------------------------------------------


def test_system_language_reads_posix_variables_in_order() -> None:
    env = {"LC_ALL": "", "LC_MESSAGES": "pt_BR.UTF-8", "LANG": "en_US.UTF-8"}
    assert system_language(environ=env, getlocale=lambda: (None, None)) == "pt-BR"


def test_system_language_skips_c_locale_and_uses_language_list() -> None:
    env = {"LC_ALL": "C", "LANGUAGE": "pt_BR:en"}
    assert system_language(environ=env, getlocale=lambda: (None, None)) == "pt-BR"


def test_system_language_falls_back_to_windows_locale_name() -> None:
    assert system_language(environ={}, getlocale=lambda: ("Portuguese_Brazil", "1252")) == "pt-BR"


def test_system_language_unknown_is_none() -> None:
    assert system_language(environ={}, getlocale=lambda: ("French_France", "1252")) is None

    def broken() -> tuple[str | None, str | None]:
        raise ValueError("unknown locale")

    assert system_language(environ={}, getlocale=broken) is None


# --- persisted config -------------------------------------------------------------------


def test_save_and_load_language_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "config.json"
    written = save_language("pt_br", path)
    assert written == path
    assert json.loads(path.read_text(encoding="utf-8")) == {"language": "pt-BR"}
    assert load_saved_language(path) == "pt-BR"


def test_save_language_keeps_other_config_keys(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"other": 1, "language": "en"}), encoding="utf-8")
    save_language("pt-BR", path)
    assert json.loads(path.read_text(encoding="utf-8")) == {"other": 1, "language": "pt-BR"}


def test_save_language_rejects_unsupported(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        save_language("fr", tmp_path / "config.json")


@pytest.mark.parametrize("content", ["", "not json", "[]", '{"language": 3}', '{"language": "xx"}'])
def test_load_saved_language_tolerates_bad_files(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.json"
    path.write_text(content, encoding="utf-8")
    assert load_saved_language(path) is None
    assert load_saved_language(tmp_path / "missing.json") is None


def test_config_file_path_honors_override(tmp_path: Path) -> None:
    target = tmp_path / "x.json"
    assert i18n.config_file_path({"SPECTRE_CONFIG_FILE": str(target)}) == target


# --- resolution order ---------------------------------------------------------------------


def _resolve(
    tmp_path: Path,
    *,
    flag: str | None = None,
    env: str | None = None,
    saved: str | None = None,
    system: str | None = None,
) -> str:
    config = tmp_path / "config.json"
    if saved is not None:
        config.write_text(json.dumps({"language": saved}), encoding="utf-8")
    environ = {"SPECTRE_LANG": env} if env is not None else {}
    return resolve_language(flag, environ=environ, config_path=config, system=lambda: system)


def test_flag_wins_over_everything(tmp_path: Path) -> None:
    assert _resolve(tmp_path, flag="en", env="pt-BR", saved="pt-BR", system="pt-BR") == "en"
    assert _resolve(tmp_path, flag="pt-BR", env="en", saved="en", system="en") == "pt-BR"


def test_env_wins_over_saved_config_and_system(tmp_path: Path) -> None:
    assert _resolve(tmp_path, env="pt-BR", saved="en", system="en") == "pt-BR"


def test_saved_config_wins_over_system(tmp_path: Path) -> None:
    assert _resolve(tmp_path, saved="pt-BR", system="en") == "pt-BR"


def test_system_locale_wins_over_default(tmp_path: Path) -> None:
    assert _resolve(tmp_path, system="pt-BR") == "pt-BR"


def test_default_is_english(tmp_path: Path) -> None:
    assert _resolve(tmp_path) == "en"


def test_invalid_env_and_config_are_skipped(tmp_path: Path) -> None:
    assert _resolve(tmp_path, env="klingon", saved="xx", system="pt-BR") == "pt-BR"


def test_invalid_flag_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _resolve(tmp_path, flag="klingon")


def test_lazy_language_follows_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPECTRE_LANG", "pt-BR")
    set_language(None)
    assert i18n.get_language() == "pt-BR"
    monkeypatch.setenv("SPECTRE_LANG", "en")
    set_language(None)
    assert i18n.get_language() == "en"
