"""Separate confidence, risk and reputation scoring.

Points come only from the InvestigationResult being scored. Explanations
name modules that actually ran. Heuristic risk never becomes CONFIRMED_BY_PROVIDER
without a provider detection count.
"""

from __future__ import annotations

from spectre_osint.core.entities import Finding, InvestigationResult, ScoreBreakdown
from spectre_osint.core.presentation import check_status_of, is_username_site_finding
from spectre_osint.core.types import EntityType, FindingStatus, RiskLevel, UsernameCheckStatus


def score_investigation(result: InvestigationResult) -> ScoreBreakdown:
    modules = {f.module for f in result.findings}
    target_type = result.target_type
    if isinstance(target_type, str):
        try:
            target_type = EntityType(target_type)
        except ValueError:
            target_type = EntityType.DOMAIN

    if target_type == EntityType.USERNAME:
        conf, conf_bd, conf_ex = _username_confidence(result)
    elif target_type in {EntityType.DOMAIN, EntityType.SUBDOMAIN}:
        conf, conf_bd, conf_ex = _domain_confidence(result, modules)
    else:
        conf, conf_bd, conf_ex = _generic_confidence(result, modules, target_type)

    risk, risk_bd, risk_ex, risk_level = _risk(result)
    rep, rep_bd, rep_ex = _reputation(result, modules, target_type, risk)

    return ScoreBreakdown(
        confidence_score=_clamp(conf),
        risk_score=_clamp(risk),
        reputation_score=_clamp(rep),
        confidence_explain=conf_ex,
        risk_explain=risk_ex,
        reputation_explain=rep_ex,
        risk_level=risk_level.value,
        confidence_breakdown=conf_bd,
        risk_breakdown=risk_bd,
        reputation_breakdown=rep_bd,
    )


def _username_confidence(result: InvestigationResult) -> tuple[int, dict[str, int], list[str]]:
    confirmed = 0
    likely = 0
    for finding in result.findings:
        if not is_username_site_finding(finding):
            continue
        status = check_status_of(finding)
        if status == UsernameCheckStatus.CONFIRMED.value:
            confirmed += 1
        elif status == UsernameCheckStatus.LIKELY.value:
            likely += 1
    breakdown = {
        "target_input": 20,
        "confirmed_public_profiles": min(confirmed * 4, 24),
        "likely_profiles": min(likely * 2, 12),
        "inconclusive_sources": 0,
    }
    total = sum(breakdown.values())
    explain = [
        f"target_input: +{breakdown['target_input']} (username validated as investigation target).",
        f"confirmed_public_profiles: +{breakdown['confirmed_public_profiles']} ({confirmed} CONFIRMED public profiles).",
        f"likely_profiles: +{breakdown['likely_profiles']} ({likely} LIKELY profiles).",
        "inconclusive_sources: +0 (inconclusive/login-wall/blocked do not raise confidence).",
    ]
    return total, breakdown, explain


def _domain_confidence(
    result: InvestigationResult, modules: set[str]
) -> tuple[int, dict[str, int], list[str]]:
    source_mods = sorted(modules & {"dns", "rdap", "crtsh", "certificates"})
    source_findings = [
        f
        for f in result.findings
        if f.module in {"dns", "rdap", "crtsh", "certificates"}
        and f.status == FindingStatus.FOUND
        and f.confidence
        and f.confidence.value in {"CONFIRMED", "HIGH"}
    ]
    evidence_n = len(result.evidence)
    breakdown = {
        "target_input": 20,
        "source_backed_records": min(len(source_findings) * 8, 32),
        "evidence_records": min(evidence_n, 15),
    }
    total = sum(breakdown.values())
    labels = "/".join(m.upper() for m in source_mods) if source_mods else "none"
    explain = [
        f"target_input: +{breakdown['target_input']} (domain validated).",
        f"source_backed_records: +{breakdown['source_backed_records']} from {len(source_findings)} FOUND records ({labels}).",
        f"evidence_records: +{breakdown['evidence_records']} from {evidence_n} evidence items in this investigation.",
    ]
    return total, breakdown, explain


def _generic_confidence(
    result: InvestigationResult, modules: set[str], target_type: EntityType
) -> tuple[int, dict[str, int], list[str]]:
    found = [f for f in result.findings if f.status == FindingStatus.FOUND]
    evidence_n = len(result.evidence)
    breakdown = {
        "target_input": 20,
        "found_modules": min(len(found) * 4, 32),
        "evidence_records": min(evidence_n, 15),
    }
    total = sum(breakdown.values())
    explain = [
        f"target_input: +{breakdown['target_input']} ({target_type.value} validated).",
        f"found_modules: +{breakdown['found_modules']} from {len(found)} FOUND findings in this investigation.",
        f"evidence_records: +{breakdown['evidence_records']} from {evidence_n} evidence items.",
    ]
    if modules:
        explain.append("modules_scored: " + ", ".join(sorted(modules)) + ".")
    return total, breakdown, explain


def _risk(
    result: InvestigationResult,
) -> tuple[int, dict[str, int], list[str], RiskLevel]:
    breakdown = {"base": 5, "provider_detections": 0, "heuristic_flags": 0, "abuse_score": 0}
    explain = ["base: +5 (unknown risk until sources in this investigation report otherwise)."]
    level = RiskLevel.LOW
    detections_total = 0
    for finding in result.findings:
        data = finding.data or {}
        detections = data.get("detections")
        if isinstance(detections, int) and detections > 0:
            add = min(detections * 4, 40)
            breakdown["provider_detections"] += add
            detections_total += detections
            explain.append(f"provider_detections: +{add} from {finding.module} ({detections} detections).")
            if detections >= 5:
                level = RiskLevel.CONFIRMED_BY_PROVIDER
            elif detections >= 1 and level == RiskLevel.LOW:
                level = RiskLevel.HIGH_RISK
        flags = data.get("heuristic_flags") or []
        if flags:
            add = min(len(flags) * 6, 24)
            breakdown["heuristic_flags"] += add
            explain.append(
                f"heuristic_flags: +{add} from {finding.module} ({', '.join(map(str, flags))}). Heuristic ≠ malicious."
            )
            if level == RiskLevel.LOW:
                level = RiskLevel.SUSPICIOUS
        abuse = data.get("abuse_score")
        if isinstance(abuse, (int, float)) and abuse:
            add = int(min(abuse, 40))
            breakdown["abuse_score"] += add
            explain.append(f"abuse_score: +{add} from {finding.module}.")
            if abuse >= 75:
                level = RiskLevel.CONFIRMED_BY_PROVIDER
            elif abuse >= 25 and level == RiskLevel.LOW:
                level = RiskLevel.SUSPICIOUS
    total = sum(breakdown.values())
    return total, breakdown, explain, level


def _reputation(
    result: InvestigationResult,
    modules: set[str],
    target_type: EntityType,
    risk: int,
) -> tuple[int, dict[str, int], list[str]]:
    breakdown = {"base": 70, "incomplete_providers": 0, "risk_penalty": 0, "clean_sources": 0}
    explain = ["base: +70 (no negative intel observed yet in this investigation)."]
    unavailable = [f for f in result.findings if f.status == FindingStatus.PROVIDER_UNAVAILABLE]
    missing = [f for f in result.findings if f.status == FindingStatus.NOT_CONFIGURED]
    if missing:
        drop = min(len(missing) * 2, 10)
        breakdown["incomplete_providers"] -= drop
        explain.append(f"incomplete_providers: -{drop} ({len(missing)} not configured).")
    if unavailable:
        drop = min(len(unavailable) * 2, 10)
        breakdown["incomplete_providers"] -= drop
        explain.append(f"incomplete_providers: -{drop} ({len(unavailable)} unavailable).")
    if risk > 30:
        drop = min(risk // 2, 40)
        breakdown["risk_penalty"] -= drop
        explain.append(f"risk_penalty: -{drop} because risk signals were present.")
    source_mods = modules & {"dns", "rdap", "crtsh"}
    if target_type in {EntityType.DOMAIN, EntityType.SUBDOMAIN} and source_mods and risk < 20:
        breakdown["clean_sources"] = 5
        labels = "/".join(sorted(m.upper() for m in source_mods))
        explain.append(f"clean_sources: +5 ({labels} resolved without risk signals).")
    total = sum(breakdown.values())
    return total, breakdown, explain


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def finding_not_configured(module: str, provider: str) -> Finding:
    return Finding(
        module=module,
        title=f"{provider} not configured",
        status=FindingStatus.NOT_CONFIGURED,
        summary="Provider not configured",
        data={"provider": provider},
    )
