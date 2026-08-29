#!/usr/bin/env bash
# Local pre-tag checklist. Does not publish, tag, or push.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

test -f README.md
test -f SECURITY.md
test -f CONTRIBUTING.md
test -f CHANGELOG.md
test -f docs/ARCHITECTURE.md
test -f docs/TESTING.md
test -f docs/RELEASE.md
test -f .env.example
test -f LICENSE

if [ -x "$ROOT/.venv/bin/python" ]; then
  PATH="$ROOT/.venv/bin:$PATH"
  export PATH
fi

python -m pytest -q
ruff check spectre_osint tests
mypy spectre_osint
pip check

ver="$(spectre --version)"
test "$ver" = "0.1.0b1"

if git ls-files | grep -Ei '\.(db|sqlite3?)$|storage_state\.json|\.env$'; then
  echo "release_check: tracked sensitive-looking artifacts" >&2
  exit 1
fi
echo "release_check: OK (version 0.1.0b1; no tag created)"
