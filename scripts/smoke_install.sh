#!/usr/bin/env bash
# Local packaging smoke test. Does not run investigations or talk to the internet
# beyond what pip may need if wheels are missing (prefer an existing cache).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/spectre-smoke.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

python3 -m venv "$TMP/venv"
# shellcheck disable=SC1091
source "$TMP/venv/bin/activate"
python -m pip install --upgrade pip >/dev/null
pip install -e "$ROOT" >/dev/null
spectre --help >/dev/null
spectre --version | grep -qx "0.1.0b1"
SPECTRE_DATA_DIR="$TMP/data" SPECTRE_REPORTS_DIR="$TMP/reports" SPECTRE_LOGS_DIR="$TMP/logs" \
  SPECTRE_DATABASE_URL="sqlite:///$TMP/data/t.db" SPECTRE_BROWSER_BACKEND=fake SPECTRE_KEYRING=false \
  spectre doctor >/dev/null
echo "smoke_install: OK"
