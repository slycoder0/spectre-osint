# Search Intelligence & Discovery Engine

[English](search-discovery.md) | [Português 🇧🇷](search-discovery.pt-BR.md)

SPECTRE's search intelligence engine (`modules/search/`) goes far beyond simple Google Dorking. It dynamically generates queries, discovers candidate profiles, extracts new indicators with provenance, classifies indicator novelty, and budgets follow-up pivots without polluting results with redundant platform hosts.

---

## The Search Intelligence Pipeline

For username investigations, the engine operates across sequential stages:

```mermaid
flowchart LR
    Planner[1. Query Planner] --> Search[2. Search Providers]
    Search --> Discover[3. Discovery Engine]
    Discover --> Extract[4. Indicator Extractor]
    Extract --> Novelty[5. Novelty Classifier]
    Novelty --> Pivot[6. Pivot Engine]
    Pivot --> Summary[7. Intelligence Summary]
```

### Stage Breakdown

| Stage | Module | Function |
| :--- | :--- | :--- |
| **1. PLANNER** | `planner.py` | Generates a deterministic set of targeted queries based on operator leads and extracted handles. |
| **2. SEARCH** | `providers.py` | Queries public search endpoints: DuckDuckGo HTML, Hacker News, Reddit, GitHub, optional loopback SearXNG, and optional Google CSE. |
| **3. DISCOVER** | `discover.py` | Identifies candidate profile URLs. **Candidates are never promoted to CONFIRMED profiles automatically.** |
| **4. EXTRACT** | `extract.py` | Extracts actionable indicators (handles, emails, personal domains, social links) with explicit `extraction_rule` tags. |
| **5. NOVELTY** | `novelty.py` | Categorizes indicators by novelty to prioritize fresh findings and avoid redundant pivots. |
| **6. PIVOT** | `pivots.py` | Generates budgeted follow-up leads (`SPECTRE_SEARCH_MAX_PIVOTS=25`, max depth 2). |
| **7. SUMMARY** | `summary.py` | Produces deterministic intelligence summaries and discovery gain metrics. |

---

## Novelty Classifications

To prevent spending discovery budget on generic platform domains or looping over operator-provided data, indicators are classified into 6 novelty states:

| Classification | Meaning | Pivot Priority |
| :--- | :--- | :--- |
| `OPERATOR_INPUT` | Value was explicitly provided by the operator in the CLI or GUI (`--alias`, `--email`, etc.). | Skipped (already known lead). |
| `KNOWN` | URL/handle matches an existing entry from the username catalog sweep. | Skipped (already verified). |
| `OBSERVED` | Directly observed within an extracted profile finding. | Ranked for enrichment. |
| `DERIVED` | Extracted from structured profile metadata (`rel="me"`, bio handles, public contact). | High priority. |
| `NOVEL` | Completely new public indicator not seen in operator input or catalog results. | Highest priority. |
| `REDUNDANT` | Belongs to a standard platform host (`github.com`, `instagram.com`, `x.com`) that should not consume pivot budgets. | Suppressed for domain pivots. |

---

## Link Hubs Exception

Standard social platform hosts are classified as `REDUNDANT` so SPECTRE does not waste query budgets discovering `github.com` or `instagram.com` as if they were personal websites.

However, **Link Hub platforms** are explicitly treated as high-value pivot targets:
- `linktr.ee`
- `beacons.ai`
- `about.me`
- `carrd.co`
- `bio.link`
- `bento.me`

When a link hub is discovered, it is prioritized for deep extraction to uncover personal blogs, portfolio domains, and secondary identities.

---

## Search Budget and Rate Limiting

The search engine respects strict operational budgets configured in `core/config.py`:
- `SPECTRE_SEARCH_QUERY_BUDGET` (Default: `12`): Maximum distinct search queries per run.
- `SPECTRE_SEARCH_MAX_PIVOTS` (Default: `25`): Maximum discovery pivots generated.
- `SPECTRE_SEARCH_MAX_DEPTH` (Default: `2`): Recursive depth limit for discovered pivots.

These limits ensure investigations terminate promptly, respect rate limits, and maintain high evidential density.
