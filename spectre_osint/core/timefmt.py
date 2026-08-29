"""Human-readable relative timestamps for CLI and GUI."""

from __future__ import annotations

from datetime import UTC, datetime


def parse_dt(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def format_ts(value: datetime | str | None) -> str:
    """Compact UTC timestamp that does not wrap on a hyphen."""
    dt = parse_dt(value)
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    total = int(round(max(0.0, float(seconds))))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def relative_age(value: datetime | str | None, *, now: datetime | None = None) -> str:
    dt = parse_dt(value)
    if dt is None:
        return "unknown"
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    seconds = int(max(0, (current - dt).total_seconds()))
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"
