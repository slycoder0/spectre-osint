"""Deterministic username match classification.

Classifies comparison between requested (operator lead) and observed usernames
into EXACT_MATCH, SIMILAR_CANDIDATE, or UNRELATED.
No fuzzy distance. No identity promotion.
"""

from __future__ import annotations

import re

EXACT_MATCH = "EXACT_MATCH"
SIMILAR_CANDIDATE = "SIMILAR_CANDIDATE"
UNRELATED = "UNRELATED"

_SEP_PATTERN = re.compile(r"[-_.]+")


def normalize_username_for_matching(value: str | None) -> str:
    """Canonical normalization for username matching: trim, strip @, lowercase."""
    return str(value or "").strip().lstrip("@").lower()


def _tokenize(handle: str) -> list[str]:
    """Split handle into constituent tokens by separator chars (-_.)."""
    return [tok for tok in _SEP_PATTERN.split(handle) if tok]


def classify_username_match(requested: str | None, observed: str | None) -> str:
    """Deterministically classify relationship between requested and observed handles.

    Returns:
        - EXACT_MATCH: identical after canonical normalization.
        - SIMILAR_CANDIDATE: recognizable variant (digits suffix/prefix, separator variance,
          common affix additions, token permutations).
        - UNRELATED: completely different handle.
    """
    req = normalize_username_for_matching(requested)
    obs = normalize_username_for_matching(observed)

    if not req or not obs:
        return UNRELATED

    # 1. Exact canonical match
    if req == obs:
        return EXACT_MATCH

    # Invariants: Do not treat variants as equal. Classify potential candidates.
    # 2. Separator variance: e.g. alice_shop vs alice-shop vs alice.shop
    req_clean_sep = _SEP_PATTERN.sub("_", req)
    obs_clean_sep = _SEP_PATTERN.sub("_", obs)
    if req_clean_sep == obs_clean_sep:
        return SIMILAR_CANDIDATE

    # Without separators: e.g. aliceshop vs alice_shop
    req_no_sep = _SEP_PATTERN.sub("", req)
    obs_no_sep = _SEP_PATTERN.sub("", obs)
    if req_no_sep and req_no_sep == obs_no_sep:
        return SIMILAR_CANDIDATE

    # 3. Numeric suffix or prefix: e.g. alice_shop vs alice_shop_1, alice_shop1, 123_alice_shop
    if re.fullmatch(rf"{re.escape(req)}[_.-]?\d+", obs):
        return SIMILAR_CANDIDATE
    if re.fullmatch(rf"\d+[_.-]?{re.escape(req)}", obs):
        return SIMILAR_CANDIDATE
    if re.fullmatch(rf"{re.escape(req_no_sep)}\d+", obs_no_sep):
        return SIMILAR_CANDIDATE

    # 4. Common platform affixes: e.g. _official, official_, real_, _real, _dev, _app, _hq, _pub
    common_affixes = (
        "official",
        "real",
        "dev",
        "app",
        "team",
        "hq",
        "pub",
        "bot",
        "io",
        "tech",
        "the",
        "my",
    )
    for affix in common_affixes:
        if obs in {f"{req}_{affix}", f"{affix}_{req}", f"{req}-{affix}", f"{affix}-{req}", f"{req}.{affix}"}:
            return SIMILAR_CANDIDATE

    # 5. Token analysis
    t_req = _tokenize(req)
    t_obs = _tokenize(obs)

    if len(t_req) >= 2 and len(t_obs) >= 2:
        # Token permutation: e.g. alice_shop vs shop_alice
        if set(t_req) == set(t_obs):
            return SIMILAR_CANDIDATE
        # Token subset with minor addition: e.g. alice_shop vs alice_shop_nyc (len diff <= 2)
        if set(t_req).issubset(set(t_obs)) and len(t_obs) <= len(t_req) + 2:
            return SIMILAR_CANDIDATE

    # 6. Strict stem boundary match: obs starts or ends with req with short addition
    if (obs.startswith(f"{req}_") or obs.startswith(f"{req}-") or obs.startswith(f"{req}.")) and len(obs) - len(req) <= 6:
        return SIMILAR_CANDIDATE
    if (obs.endswith(f"_{req}") or obs.endswith(f"-{req}") or obs.endswith(f".{req}")) and len(obs) - len(req) <= 6:
        return SIMILAR_CANDIDATE

    return UNRELATED
