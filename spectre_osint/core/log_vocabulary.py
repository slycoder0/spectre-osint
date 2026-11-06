"""The words SPECTRE's own log lines are made of, derived from the code (B2-07).

The log safety net (`core/redaction.py`) replaces registered target values in log lines.
A form that is also one of these words (`github`, `timeout`, `AUTHENTICATED_PUBLIC`,
`ReadTimeout`, `retry_after`, ...) is never registered: replacing it would turn
`provider=github` into `provider=t:…` in every line of the investigation while hiding
nothing, because those words are the log's structure, not the target. Keeping a short
or common target out of a line is the call site's job, checked by the canary
(`tests/test_logs_no_target_data.py`), not the safety net's.

Everything is read from the code, not kept as a list:

- site names and slugs of the bundled catalog (`load_sites()`);
- names and values of the `Enum`s defined in the package (`Confidence`, `AccessMode`, ...);
- names of the exception classes loaded in the process (`ReadTimeout`, `SSRFBlocked`, ...);
- every word of every log message template in the package: the constant format strings
  of `logger.*()` calls, read from the package's source files. A frozen build without
  `.py` files gets no template words, so it scrubs more, never less.

`tests/test_target_redaction.py` checks the template scan against an AST parse of every
log call, so a new log line cannot slip past it.
"""

from __future__ import annotations

import enum
import functools
import re
from collections.abc import Iterator
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent

# `<receiver>.<method>(` followed by one or more adjacent string literals (implicit
# concatenation across lines included). `logger.log(LEVEL, "...")` skips the level.
_LOG_TEMPLATE = re.compile(
    r"\.(?:debug|info|warning|warn|error|exception|critical|log)\(\s*"
    r"(?:[A-Za-z_][\w.]*\s*,\s*)?"
    r"((?:[rRuU]?(?:\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*')\s*)+)"
)
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


def template_words(source: str) -> set[str]:
    """Every word of the log message templates found in one module's source text."""
    words: set[str] = set()
    for match in _LOG_TEMPLATE.finditer(source):
        words.update(_WORD.findall(match.group(1)))
    return words


def _package_template_words() -> set[str]:
    words: set[str] = set()
    for path in _PACKAGE_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            words |= template_words(path.read_text(encoding="utf-8"))
        except OSError:
            continue
    return words


def _subclasses(root: type) -> Iterator[type]:
    seen: set[type] = set()
    stack = [root]
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        yield cls
        try:
            stack.extend(cls.__subclasses__())
        except TypeError:  # `type.__subclasses__` needs an instance of type
            continue


def _enum_words() -> set[str]:
    # Import the modules that define the shared enums, so the result does not depend on
    # which command happened to import what first.
    from spectre_osint.core import progress, types  # noqa: F401

    words: set[str] = set()
    for cls in _subclasses(enum.Enum):
        if not issubclass(cls, enum.Enum) or not cls.__module__.startswith("spectre_osint."):
            continue
        for member in cls.__members__.values():
            words.add(member.name)
            words.add(str(member.value))
    return words


def _exception_words() -> set[str]:
    return {cls.__name__ for cls in _subclasses(BaseException)}


def _catalog_words() -> set[str]:
    try:
        from spectre_osint.modules.username.engine import load_sites

        sites = load_sites()
    except Exception:  # noqa: BLE001 — a broken catalog must not break logging
        return set()
    words: set[str] = set()
    for site in sites:
        for key in ("name", "slug"):
            value = str(site.get(key) or "").strip()
            if value:
                words.add(value)
    return words


@functools.lru_cache(maxsize=1)
def log_vocabulary() -> frozenset[str]:
    """Case-folded words the safety net never registers. Built once per process."""
    words = _catalog_words() | _enum_words() | _exception_words() | _package_template_words()
    return frozenset(word.casefold() for word in words if word)
