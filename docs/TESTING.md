# Testing

Do not write “tests pass” unless you ran the command in this repository.

Working directory: the git root. Prefer the project venv (`.venv`).

## Commands that exist

```bash
# unit/integration (default suite)
pytest
# or quieter
pytest -q

# lint / types / deps
ruff check spectre_osint tests
mypy spectre_osint
pip check

# vulnerability scan (dev extra; also in CI)
pip-audit

# install diagnostics (no investigation, no secrets printed)
spectre --version          # asserts 0.1.0b1
spectre doctor
spectre doctor --json

# packaging smoke: temp venv, pip install -e ., help + doctor, then delete
bash scripts/smoke_install.sh

# local pre-tag checklist (does NOT tag/push; asserts 0.1.0b1)
bash scripts/release_check.sh
```

CI (`.github/workflows/ci.yml`) on Python 3.12 and 3.13: pip check, pytest with
coverage, ruff, mypy, pip-audit.

Dev install: `pip install -e ".[dev]"`.

## Quick validation

Use when the change is documentation-only or a tiny isolated module:

```bash
git diff --check
ruff check spectre_osint tests
```

If you only edited `docs/` / `README.md`, `git diff --check` is the
minimum. Still run pytest if you also touched `spectre_osint/` or `tests/`.

## Module-level validation

Run the tests that cover the code you changed, for example:

```bash
pytest tests/test_doctor.py -q
pytest tests/test_search_intelligence.py -q
pytest tests/test_username_identity.py -q
```

Then ruff + mypy if Python changed.

## Full release validation

```bash
pytest
ruff check spectre_osint tests
mypy spectre_osint
pip check
pip-audit
bash scripts/smoke_install.sh
bash scripts/release_check.sh
spectre doctor
git status
git ls-files | grep -Ei '\.(db|sqlite3?)$|storage_state|\.env$' && echo FAIL
```

`release_check.sh` asserts version `0.1.0b1`.

## Rules

- Fixtures are synthetic (`alice_osint`, `alice_example`). No live personal accounts.
- Tests must not require real API keys or real browser logins (fake backend in `conftest.py`).
- Doctor tests assert secrets never appear and investigations never start.
- Preserve the existing suite; do not delete failing tests to “go green”.
