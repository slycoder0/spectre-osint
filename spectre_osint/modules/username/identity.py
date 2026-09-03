"""Public-profile identity correlation. Same username is never enough."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import (
    Confidence,
    EntityType,
    FindingStatus,
    RelationType,
    UsernameCheckStatus,
)

logger = get_logger("spectre.username")

# Conservative pairwise weights. Same username is weak on purpose.
WEIGHTS = {
    "same_username": 6,
    "same_display_name": 16,
    "similar_bio": 10,
    "same_organization": 10,
    "same_location": 8,
    "same_personal_domain": 42,
    "same_personal_url": 40,
    "cross_profile_link": 38,
    "same_public_id": 32,
    "same_public_email": 35,
    "same_avatar_url": 18,
}
CONFLICTS = {
    "distinct_display_name": -28,
    "distinct_personal_domain": -32,
    "distinct_organization": -18,
    "distinct_location": -12,
    "distinct_public_id": -40,
    "distinct_public_email": -35,
}
BANDS = (
    (80, "STRONG"),
    (60, "LIKELY"),
    (30, "POSSIBLE"),
    (0, "LOW"),
)
CLUSTER_MIN = 60
GENERIC_BIOS = frozenset(
    {
        "",
        "no bio",
        "none",
        "n/a",
        "na",
        "hello",
        "hello world",
        "hey",
        "available",
        "this is my bio",
    }
)
_TRACKING_QUERY = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
        "igshid",
        "mc_cid",
        "mc_eid",
        "ref",
        "referrer",
    }
)
_PLATFORM_HOSTS = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "reddit.com",
        "news.ycombinator.com",
        "dev.to",
        "medium.com",
        "keybase.io",
        "hub.docker.com",
        "npmjs.com",
        "pypi.org",
        "replit.com",
        "kaggle.com",
        "pinterest.com",
        "tumblr.com",
        "steamcommunity.com",
        "youtube.com",
        "twitch.tv",
        "vimeo.com",
        "soundcloud.com",
        "last.fm",
        "chess.com",
        "lichess.org",
        "bsky.app",
        "mastodon.social",
        "linktr.ee",
        "hackerone.com",
        "bugcrowd.com",
        "behance.net",
        "dribbble.com",
        "artstation.com",
        "flickr.com",
        "t.me",
        "telegram.me",
        "instagram.com",
        "facebook.com",
        "threads.net",
        "tiktok.com",
        "x.com",
        "twitter.com",
        "linkedin.com",
    }
)


def normalize_name(value: str | None) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = re.sub(r"[^a-z0-9\s]", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


def normalize_username(value: str | None) -> str:
    return str(value or "").strip().lstrip("@").lower()


def normalize_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def normalize_location(value: str | None) -> str:
    return normalize_name(value)


def normalize_url(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return None
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=False)
        if k.lower() not in _TRACKING_QUERY
    ]
    netloc = host
    if parsed.port and parsed.port not in {80, 443}:
        netloc = f"{host}:{parsed.port}"
    return urlunparse(("https", netloc, path or "/", "", urlencode(query), ""))


def normalize_domain(value: str | None) -> str | None:
    url = normalize_url(value) if value and "/" in str(value) else None
    host = urlparse(url).hostname if url else str(value or "").strip().lower()
    if not host:
        if value:
            host = str(value).strip().lower()
        else:
            return None
    if host.startswith("www."):
        host = host[4:]
    host = host.split(":")[0]
    if not host or host in _PLATFORM_HOSTS:
        return None
    return host


def avatar_key(url: str | None) -> str:
    canon = normalize_url(url)
    if not canon:
        return ""
    parsed = urlparse(canon)
    stripped = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
    return hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:16]


def correlation_band(score: int) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "LOW"


@dataclass
class IdentityRecord:
    platform: str
    username: str
    profile_url: str
    display_name: str = ""
    bio: str = ""
    avatar_url: str = ""
    website: str = ""
    location: str = ""
    organization: str = ""
    public_email: str = ""
    public_id: str = ""
    links: list[str] = field(default_factory=list)
    created: str = ""
    check_status: str = ""
    entity_id: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def name_n(self) -> str:
        return normalize_name(self.display_name)

    @property
    def bio_n(self) -> str:
        return normalize_text(self.bio)

    @property
    def domain(self) -> str:
        return normalize_domain(self.website) or ""

    @property
    def url_n(self) -> str:
        return normalize_url(self.website) or ""

    @property
    def profile_n(self) -> str:
        return normalize_url(self.profile_url) or self.profile_url

    @property
    def avatar_n(self) -> str:
        return avatar_key(self.avatar_url)

    @property
    def loc_n(self) -> str:
        return normalize_location(self.location)

    @property
    def org_n(self) -> str:
        return normalize_name(self.organization)

    @property
    def email_n(self) -> str:
        return str(self.public_email or "").strip().lower()

    @property
    def id_n(self) -> str:
        return str(self.public_id or "").strip().lower()

    @property
    def key(self) -> str:
        return f"{self.platform}::{self.username}"


def records_from_findings(findings: list[Finding]) -> list[IdentityRecord]:
    rows: list[IdentityRecord] = []
    for finding in findings:
        data = finding.data or {}
        status = str(data.get("check_status") or "")
        if status not in {UsernameCheckStatus.CONFIRMED.value, UsernameCheckStatus.LIKELY.value}:
            continue
        if finding.module != "username":
            continue
        if finding.title in {"Username sweep", "Identity correlation"}:
            continue
        if str(data.get("not_profile") or "") or str(data.get("kind") or "") in {"name", "email", "domain"}:
            continue
        observed = data.get("observed") if isinstance(data.get("observed"), dict) else {}
        links = [str(x) for x in (data.get("public_links") or []) if x]
        website = str(data.get("website") or "")
        if website and website not in links:
            links.append(website)
        rows.append(
            IdentityRecord(
                platform=str(data.get("platform") or finding.title),
                username=normalize_username(data.get("username")),
                profile_url=str(data.get("profile_url") or data.get("final_url") or ""),
                display_name=str(data.get("display_name") or ""),
                bio=str(data.get("bio") or "")[:300],
                avatar_url=str(data.get("avatar_url") or ""),
                website=website,
                location=str(data.get("public_location") or data.get("location") or ""),
                organization=str(data.get("organization") or data.get("company") or ""),
                public_email=str(data.get("public_email") or data.get("email") or ""),
                public_id=str(data.get("public_id") or data.get("id") or ""),
                links=links,
                provenance=dict(observed or {}),
                created=str(data.get("created_at") or data.get("created") or ""),
                check_status=status,
                entity_id=Entity.create(
                    EntityType.SOCIAL_PROFILE,
                    str(data.get("profile_url") or data.get("final_url") or finding.title),
                    str(data.get("platform") or finding.title),
                    Confidence.MEDIUM,
                ).id,
            )
        )
    rows.sort(key=lambda r: (r.platform.lower(), r.profile_url))
    return rows


def _generic_bio(text: str) -> bool:
    if len(text) < 16:
        return True
    return text in GENERIC_BIOS


def _bio_similar(a: str, b: str) -> bool:
    if _generic_bio(a) or _generic_bio(b):
        return False
    if a == b:
        return True
    # Conservative token overlap; not NLP identity.
    left = {tok for tok in a.split() if len(tok) > 3}
    right = {tok for tok in b.split() if len(tok) > 3}
    if len(left) < 3 or len(right) < 3:
        return False
    overlap = len(left & right) / max(len(left | right), 1)
    return overlap >= 0.65


def _name_conflict(a: str, b: str) -> bool:
    if not a or not b or a == b:
        return False
    ta, tb = a.split(), b.split()
    if len(ta) < 2 or len(tb) < 2:
        return False
    if a in b or b in a:
        return False
    return True


def _link_points_at(record: IdentityRecord, other: IdentityRecord) -> bool:
    """True when record publicly links to other's *profile*."""
    # other.website is deliberately not a target. Two profiles carrying the same
    # website is one observation, already scored by same_personal_domain /
    # same_personal_url; treating it as a link as well counts it twice.
    targets = {other.profile_n}
    for raw in record.links + [record.website, record.profile_url]:
        canon = normalize_url(raw)
        if canon and canon in targets:
            return True
        host = normalize_domain(raw)
        other_host = urlparse(other.profile_n).hostname or ""
        if host and other_host and host == other_host.removeprefix("www."):
            path = urlparse(canon or "").path.lower()
            if other.username and other.username in path:
                return True
    return False


_EVIDENCE_FIELDS = {
    "same_display_name": "display_name",
    "distinct_display_name": "display_name",
    "similar_bio": "bio",
    "same_organization": "organization",
    "distinct_organization": "organization",
    "same_location": "location",
    "distinct_location": "location",
    "same_personal_domain": "website",
    "distinct_personal_domain": "website",
    "same_personal_url": "website",
    "cross_profile_link": "links",
    "same_public_id": "public_id",
    "distinct_public_id": "public_id",
    "same_public_email": "public_email",
    "distinct_public_email": "public_email",
    "same_avatar_url": "avatar_url",
}


def _observed_side(record: IdentityRecord, field: str) -> dict[str, str]:
    prov = record.provenance.get(field) if isinstance(record.provenance, dict) else None
    if isinstance(prov, dict) and prov.get("value"):
        value = prov.get("value")
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        return {
            "value": str(value),
            "source": str(prov.get("source") or ""),
            "observed_at": str(prov.get("observed_at") or ""),
        }
    raw = {
        "display_name": record.display_name,
        "bio": record.bio,
        "organization": record.organization,
        "location": record.location,
        "website": record.website,
        "public_id": record.public_id,
        "public_email": record.public_email,
        "avatar_url": record.avatar_url,
        "links": ", ".join(record.links),
    }.get(field, "")
    return {"value": str(raw or ""), "source": "", "observed_at": ""}


def _evidence_detail(
    left: IdentityRecord,
    right: IdentityRecord,
    evidence: list[str],
    conflicts: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for code in evidence + conflicts:
        field = _EVIDENCE_FIELDS.get(code)
        if not field:
            continue
        rows.append(
            {
                "code": code,
                "kind": "conflict" if code in conflicts else "evidence",
                "left": _observed_side(left, field),
                "right": _observed_side(right, field),
            }
        )
    return rows


def compare_records(left: IdentityRecord, right: IdentityRecord) -> dict[str, Any]:
    if (left.platform, left.username) > (right.platform, right.username):
        left, right = right, left
    evidence: list[str] = []
    conflicts: list[str] = []
    score = 0
    if left.username and left.username == right.username:
        evidence.append("same_username")
        score += WEIGHTS["same_username"]
    if left.name_n and left.name_n == right.name_n:
        evidence.append("same_display_name")
        score += WEIGHTS["same_display_name"]
    elif _name_conflict(left.name_n, right.name_n):
        conflicts.append("distinct_display_name")
        score += CONFLICTS["distinct_display_name"]
    if left.bio_n and right.bio_n and _bio_similar(left.bio_n, right.bio_n):
        evidence.append("similar_bio")
        score += WEIGHTS["similar_bio"]
    if left.org_n and left.org_n == right.org_n:
        evidence.append("same_organization")
        score += WEIGHTS["same_organization"]
    elif left.org_n and right.org_n and left.org_n != right.org_n:
        conflicts.append("distinct_organization")
        score += CONFLICTS["distinct_organization"]
    if left.loc_n and left.loc_n == right.loc_n:
        evidence.append("same_location")
        score += WEIGHTS["same_location"]
    elif left.loc_n and right.loc_n and left.loc_n != right.loc_n:
        conflicts.append("distinct_location")
        score += CONFLICTS["distinct_location"]
    # normalize_domain() and normalize_url() are two views of one observed website
    # value, so both codes are reported but only the strongest one scores.
    website_signals: list[str] = []
    if left.domain and left.domain == right.domain:
        evidence.append("same_personal_domain")
        website_signals.append("same_personal_domain")
    elif left.domain and right.domain and left.domain != right.domain:
        conflicts.append("distinct_personal_domain")
        score += CONFLICTS["distinct_personal_domain"]
    if left.url_n and left.url_n == right.url_n:
        evidence.append("same_personal_url")
        website_signals.append("same_personal_url")
    if website_signals:
        score += max(WEIGHTS[code] for code in website_signals)
    if _link_points_at(left, right) or _link_points_at(right, left):
        evidence.append("cross_profile_link")
        score += WEIGHTS["cross_profile_link"]
    if left.id_n and left.id_n == right.id_n:
        evidence.append("same_public_id")
        score += WEIGHTS["same_public_id"]
    elif left.id_n and right.id_n and left.id_n != right.id_n:
        conflicts.append("distinct_public_id")
        score += CONFLICTS["distinct_public_id"]
    if left.email_n and left.email_n == right.email_n:
        evidence.append("same_public_email")
        score += WEIGHTS["same_public_email"]
    elif left.email_n and right.email_n and left.email_n != right.email_n:
        conflicts.append("distinct_public_email")
        score += CONFLICTS["distinct_public_email"]
    if left.avatar_n and left.avatar_n == right.avatar_n:
        evidence.append("same_avatar_url")
        score += WEIGHTS["same_avatar_url"]

    evidence = sorted(set(evidence))
    conflicts = sorted(set(conflicts))
    strong_conflict = bool(
        {"distinct_public_id", "distinct_public_email"} & set(conflicts)
        or ({"distinct_personal_domain", "distinct_display_name"} <= set(conflicts))
    )
    score = max(0, min(100, score))
    if strong_conflict:
        score = min(score, 24)
    band = correlation_band(score)
    explain = [f"+ {tag}" for tag in evidence] + [f"- {tag}" for tag in conflicts]
    if not explain:
        explain = ["+ same_username only" if "same_username" in evidence else "no comparable public fields"]
    logger.debug(
        "identity correlation %s <-> %s score=%s evidence=%s conflicts=%s",
        f"{left.platform.lower()}::{left.username}",
        f"{right.platform.lower()}::{right.username}",
        score,
        ",".join(evidence) or "none",
        ",".join(conflicts) or "none",
    )
    return {
        "left": left.platform,
        "right": right.platform,
        "left_key": left.key,
        "right_key": right.key,
        "left_username": left.username,
        "right_username": right.username,
        "score": score,
        "band": band,
        "evidence": evidence,
        "conflicts": conflicts,
        "explain": explain,
        "strong_conflict": strong_conflict,
        "evidence_detail": _evidence_detail(left, right, evidence, conflicts),
    }


def _pair_keys(pair: dict[str, Any]) -> tuple[str, str]:
    left = str(pair.get("left_key") or pair.get("left") or "")
    right = str(pair.get("right_key") or pair.get("right") or "")
    return (left, right) if left <= right else (right, left)


def _cluster_profiles(records: list[IdentityRecord], pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mixed = len({r.username for r in records if r.username}) > 1
    by_name = {r.key: r for r in records}
    parent = {r.key: r.key for r in records}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def cluster_of(root: str) -> list[str]:
        return sorted(p for p in parent if find(p) == root)

    def label_of(key: str) -> str:
        rec = by_name[key]
        if mixed:
            return f"{rec.platform} ({rec.username})"
        return rec.platform

    ranked = sorted(pairs, key=lambda p: (-int(p["score"]), p["left"], p["right"]))
    pair_index = {_pair_keys(p): p for p in pairs}
    for pair in ranked:
        if int(pair["score"]) < CLUSTER_MIN or pair["strong_conflict"]:
            continue
        a, b = pair.get("left_key") or pair["left"], pair.get("right_key") or pair["right"]
        ra, rb = find(a), find(b)
        if ra == rb:
            continue
        members = cluster_of(ra) + cluster_of(rb)
        blocked = False
        for i, left in enumerate(members):
            for right in members[i + 1 :]:
                key = (left, right) if left < right else (right, left)
                info = pair_index.get(key)
                if info and (info["strong_conflict"] or int(info["score"]) < CLUSTER_MIN):
                    blocked = True
                    break
            if blocked:
                break
        if blocked:
            continue
        parent[rb] = ra

    clusters: list[dict[str, Any]] = []
    seen: set[str] = set()
    for platform in sorted(parent):
        root = find(platform)
        if root in seen:
            continue
        members = cluster_of(root)
        seen.add(root)
        if len(members) < 2:
            continue
        member_pairs = []
        for i, left in enumerate(members):
            for right in members[i + 1 :]:
                key = (left, right) if left < right else (right, left)
                info = pair_index.get(key)
                if info:
                    member_pairs.append(info)
        score = min((int(p["score"]) for p in member_pairs), default=0)
        evidence = sorted({tag for p in member_pairs for tag in p["evidence"]})
        conflicts = sorted({tag for p in member_pairs for tag in p["conflicts"]})
        clusters.append(
            {
                "id": "cluster-" + hashlib.sha256("|".join(members).encode()).hexdigest()[:10],
                "platforms": [label_of(p) for p in members],
                "score": score,
                "band": correlation_band(score),
                "evidence": evidence,
                "conflicts": conflicts,
                "explain": [f"+ {tag}" for tag in evidence] + [f"- {tag}" for tag in conflicts],
                "profiles": [
                    {
                        "platform": by_name[p].platform,
                        "username": by_name[p].username,
                        "profile_url": by_name[p].profile_url,
                        "display_name": by_name[p].display_name,
                    }
                    for p in members
                ],
            }
        )
    clusters.sort(key=lambda c: (c["platforms"], -int(c["score"])))
    return clusters


def correlate_identities(findings: list[Finding]) -> dict[str, Any]:
    records = records_from_findings(findings)
    pairs = [
        compare_records(records[i], records[j])
        for i in range(len(records))
        for j in range(i + 1, len(records))
    ]
    clusters = _cluster_profiles(records, pairs)
    mixed = len({r.username for r in records if r.username}) > 1
    clustered = {p for c in clusters for p in c["platforms"]}
    unclustered = []
    for rec in records:
        label = f"{rec.platform} ({rec.username})" if mixed else rec.platform
        if label not in clustered:
            unclustered.append(label)
    payload = {
        "records": len(records),
        "pairs": pairs,
        "clusters": clusters,
        "unclustered": unclustered,
        "max_score": max((int(p["score"]) for p in pairs), default=0),
        "notes": [
            "Same username is a weak signal and is never sufficient for identity.",
            "Scores are conservative public-evidence estimates, not civil identification.",
        ],
    }
    return payload


def identity_artifacts(findings: list[Finding], username_entity: Entity) -> dict[str, Any]:
    payload = correlate_identities(findings)
    entities: list[Entity] = []
    relationships: list[Relationship] = []
    extra_findings: list[Finding] = []
    records = records_from_findings(findings)
    by_key = {r.key: r for r in records}
    for pair in payload["pairs"]:
        left = by_key.get(str(pair.get("left_key") or ""))
        right = by_key.get(str(pair.get("right_key") or ""))
        if not left or not right or not left.entity_id or not right.entity_id:
            continue
        if int(pair["score"]) < 30:
            continue
        relationships.append(
            Relationship(
                from_entity_id=left.entity_id,
                to_entity_id=right.entity_id,
                relation=RelationType.IDENTITY_LINK,
                source="identity-correlation",
                confidence=Confidence.HIGH if pair["band"] in {"STRONG", "LIKELY"} else Confidence.MEDIUM,
                metadata={
                    "score": pair["score"],
                    "band": pair["band"],
                    "evidence": pair["evidence"],
                    "conflicts": pair["conflicts"],
                    "not_civil_id": True,
                },
            )
        )
    mixed = len({r.username for r in records if r.username}) > 1
    label_to_rec = {
        (f"{r.platform} ({r.username})" if mixed else r.platform): r for r in records
    }
    for index, cluster in enumerate(payload["clusters"], 1):
        person = Entity.create(
            EntityType.PERSON,
            f"public-identity-candidate-{index}",
            source="identity-correlation",
            confidence=Confidence.HIGH if cluster["band"] in {"STRONG", "LIKELY"} else Confidence.MEDIUM,
            tags=["identity-candidate", "public-only"],
            metadata={
                "cluster_id": cluster["id"],
                "platforms": cluster["platforms"],
                "score": cluster["score"],
                "band": cluster["band"],
                "not_civil_id": True,
            },
        )
        entities.append(person)
        for platform in cluster["platforms"]:
            rec = label_to_rec.get(platform)
            if rec and rec.entity_id:
                relationships.append(
                    Relationship(
                        from_entity_id=person.id,
                        to_entity_id=rec.entity_id,
                        relation=RelationType.HAS_PROFILE,
                        source="identity-correlation",
                        confidence=person.confidence,
                        metadata={"cluster_id": cluster["id"], "not_civil_id": True},
                    )
                )
    if payload["records"] >= 2:
        extra_findings.append(
            Finding(
                module="username",
                title="Identity correlation",
                status=FindingStatus.FOUND if payload["clusters"] else FindingStatus.INCONCLUSIVE,
                summary=(
                    f"{len(payload['clusters'])} public identity cluster(s); "
                    f"max pairwise score {payload['max_score']}"
                ),
                data=payload,
                confidence=Confidence.MEDIUM if payload["clusters"] else Confidence.LOW,
                entity_id=username_entity.id,
            )
        )
    return {
        "identity_correlation": payload,
        "entities": entities,
        "relationships": relationships,
        "findings": extra_findings,
    }
