"""Timeline building never crashes on mixed naive / aware timestamps.

Found during the B2-07 live check: `spectre domain example.com` exited 1 with
"can't compare offset-naive and offset-aware datetimes" because RDAP dates carry an
offset ("...Z") while certificate / first_seen dates do not, and undated events sort as
the aware `utcnow()`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from spectre_osint.core.entities import Finding, InvestigationResult
from spectre_osint.core.pipeline import _timeline_from_result
from spectre_osint.core.types import EntityType, FindingStatus


def _result(*findings: Finding) -> InvestigationResult:
    return InvestigationResult(
        case_id="case",
        case_name="case",
        target="example.com",
        target_type=EntityType.DOMAIN,
        mode="passive",
        started_at=datetime.now(UTC),
        findings=list(findings),
    )


def test_mixed_naive_and_aware_dates_sort_without_error() -> None:
    result = _result(
        Finding(
            module="rdap",
            title="RDAP",
            status=FindingStatus.FOUND,
            summary="synthetic",
            data={"events": [{"action": "registration", "date": "1995-08-14T04:00:00Z"}]},
        ),
        Finding(
            module="crtsh",
            title="CT",
            status=FindingStatus.FOUND,
            summary="synthetic",
            data={"timeline": [{"date": "2024-01-02 03:04:05", "label": "certificate issued"}]},
        ),
        Finding(
            module="wayback",
            title="Wayback",
            status=FindingStatus.FOUND,
            summary="synthetic",
            data={"first_seen": "20000101"},
        ),
        Finding(
            module="rdap",
            title="RDAP undated",
            status=FindingStatus.FOUND,
            summary="synthetic",
            data={"events": [{"action": "last changed", "date": ""}]},
        ),
    )
    events = _timeline_from_result(result)
    labels = [event.label for event in events]
    assert labels[:3] == ["RDAP registration", "wayback first_seen", "certificate issued"]
    assert labels[-1] == "RDAP last changed"  # undated: sorted as "now"
