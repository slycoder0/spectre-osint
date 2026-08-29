# Release

SPECTRE is **beta `0.1.0b1` (validated on CI, ready to tag)**. Tag has **not** been executed.

Reading this file is **not** authorization to tag.

## Channel

```
0.1.0b1 (validated on CI)  →  remote tag & release  →  later betas  →  stable
```

`CHANGELOG.md` uses Keep a Changelog. Until a tag exists, work stays under
`[Unreleased]`.

Version source: `spectre_osint/__init__.py` → `__version__`
(setuptools dynamic version in `pyproject.toml`).

## 0.1.0b1 process (do not run until asked)

1. **Preflight**
   - `git status` clean
   - Review milestone checklist and release readiness
   - Confirm no tracked `.env` / `*.db` / `storage_state` / real reports
   - `spectre doctor` is not ACTION REQUIRED on a clean install
2. **Version bump** (explicit commit)
   - `__version__ = "0.1.0b1"`
   - Update version assertions in `scripts/smoke_install.sh` and `scripts/release_check.sh`
   - Classifier in `pyproject.toml` may stay Alpha until stable
3. **CHANGELOG**
   - Add `## [0.1.0b1] - YYYY-MM-DD` from Unreleased
   - Keep a new empty `[Unreleased]`
4. **Tests / security**
   - `pytest`, ruff, mypy, pip check, pip-audit
   - `bash scripts/smoke_install.sh`
   - `bash scripts/release_check.sh` (asserts version `0.1.0b1`)
5. **Docs metadata**
6. **Tag** (explicit request only)
   - Annotated tag `0.1.0b1` on the bump commit
7. **Push** (explicit request only)
   - `main` then tags. Local main may be many commits ahead of origin; the operator
     must accept publishing that history.
8. **GitHub Release** (explicit request only)
   - From the tag; attach no real reports, no `.env`, no session files

## Rollback / recovery

If a bad tag or release is published:

- Do **not** force-push `main` unless the operator explicitly orders a history rewrite
  (default: never rewrite).
- Yank a GitHub Release as draft/unpublished if the UI allows.
- Push a follow-up commit + tag (`0.1.0b2`) that fixes the issue.
- If a secret landed in git: rotate the secret; treat history as compromised; do not
  “fix” it only by deleting the file on `main`.

If `release_check.sh` or CI fails after a bump, **do not tag**. Reset the bump commit
only if it has not been pushed (`git reset --soft HEAD~1` locally, operator-approved).

## What this tree already has

- `scripts/smoke_install.sh` — clean venv install + `spectre --help` + `spectre doctor`
- `scripts/release_check.sh` — required docs, pytest, ruff, mypy, pip check, version pin,
  forbidden tracked artifacts
- CI workflow as a second gate after a future push
