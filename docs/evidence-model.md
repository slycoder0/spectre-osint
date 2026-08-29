# SPECTRE Evidence Model & Invariants

[English](evidence-model.md) | [Português 🇧🇷](evidence-model.pt-BR.md)

SPECTRE is built upon strict evidential boundaries. It treats online investigations with legal and technical honesty: **observed public data is recorded faithfully, provenance is preserved, and identity is never assumed.**

---

## Core Evidential Invariants

The following rules are hardcoded into the architecture and cannot be violated:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CORE EVIDENTIAL INVARIANTS                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Same username ≠ Same person (username reuse does not imply identity)   │
│  2. HTTP 200 alone ≠ CONFIRMED status (must match verified profile markup) │
│  3. Operator input ≠ Observed evidence (leads are kept strictly distinct)  │
│  4. Search candidate ≠ Confirmed profile (discovery hits stay unconfirmed) │
│  5. AUTHENTICATED_PUBLIC ≠ Private access (operator session on public web)  │
│  6. NOT_FOUND ≠ Account does not exist (only means absent at checked URL)  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Catalog Status Classifications

When SPECTRE queries public platforms in `data/sites.yaml`, each provider yields a deterministic `UsernameCheckStatus`:

| Status | Meaning | Evidential Interpretation |
| :--- | :--- | :--- |
| `CONFIRMED` | Platform-specific profile markers matched conclusively. | Verified public profile presence. **Not** civil identity proof. |
| `LIKELY` | Strong public indicators found, but missing definitive anchor. | Probable profile presence. Requires operator review. |
| `INCONCLUSIVE` | Page loaded but content was ambiguous or anti-bot challenge occurred. | Inconclusive finding. No identity assumption made. |
| `NOT_FOUND` | Platform returned standard 404 or profile-not-found indicator. | Profile not observed at target URL. |
| `BLOCKED` | WAF, Cloudflare, or edge filter blocked the request. | Platform inaccessible. SPECTRE does not bypass filters. |
| `LOGIN_REQUIRED` | Platform requires an authenticated session to view the profile. | Public profile walled. May be viewed via `AUTHENTICATED_PUBLIC`. |
| `RATE_LIMITED` | HTTP 429 received or platform quota exceeded. | Temporary limit. Backs off without IP rotation. |
| `OBSERVED` | Indexed public reference or mention found via search. | Public mention. **Never** promoted to catalog `LIKELY`/`CONFIRMED`. |
| `NOT_CONFIGURED` | Optional API provider key or SearXNG is unconfigured. | Skipped provider. Investigation continues normally. |
| `PROVIDER_UNAVAILABLE`| Network timeout or deterministic failure after retry exhaustion. | Source unavailable. Investigation continues with remaining sources. |

---

## Operator Input vs. Observed Provenance

SPECTRE maintains an absolute distinction between what the investigator inputs and what was observed on the public web:

- **Operator Input (`source="user"`):**
  - Target username, `--alias`, `--name`, `--email`, `--website`.
  - Treated as hypothesis/leads.
  - Stored with `confidence=CONFIRMED` only in the semantic sense of *"this is the operator's declared target"*, never as verified proof of personhood.
- **Observed Evidence (`source="observed"` / `source="platform"`):**
  - Titles, bio text, avatar URLs, outbound links (`rel="me"`), public emails extracted from profile pages.
  - Carries immutable provenance detailing the exact URL, platform, and extraction rule.
  - Generic platform branding (e.g., `"TryHackMe | Cyber Security Training"`) is rejected and stripped from identity summaries.

---

## Conservative Identity Correlation

The identity correlation engine (`modules/username/identity.py`) correlates pairs of confirmed/likely profiles:

1. **Frozen Weights:** Explicit match weights are assigned to shared attributes (avatar hash, verified social links, unique bio handles, shared emails).
2. **Same-Username Baseline:** Sharing the same handle across platforms is treated as a weak signal, preventing false-positive clustering.
3. **Conflict Detection:** Contradictory biographical signals penalize correlation scores.
4. **Bands of Overlap:**
   - `LOW` (Score < 30): Weak public overlap.
   - `POSSIBLE` (Score 30–59): Possible public overlap.
   - `LIKELY` (Score 60–84): Likely public overlap.
   - `STRONG` (Score >= 85): Strong public overlap.

---

## Scoring Model

The scoring engine (`core/scoring.py`) calculates confidence, risk indicators, and public footprint scores for the specific investigation run:
- **Confidence Score:** Derived solely from verified evidence and solid correlation links.
- **Risk Indicators:** Signals such as account exposure in known breaches, flagged handles, or exposed infrastructure.
- **Footprint Metrics:** Breadth of public digital presence across domains and platforms.

Artifacts, SQLite cases, and HTML reports remain strictly stored on your local disk.
