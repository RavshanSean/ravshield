from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def is_expired(
    expires_at: datetime | None,
    *,
    now: datetime | None = None,
) -> bool:
    """
    Return True when a reputation record has passed its TTL.
    """

    if expires_at is None:
        return False

    current = now or utc_now()

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    return current >= expires_at


def clamp_unit_interval(value: float) -> float:
    return max(0.0, min(float(value), 1.0))


def effective_confidence(
    confidence: float,
    source_confidence: float = 1.0,
    *,
    expires_at: datetime | None = None,
    now: datetime | None = None,
) -> float:
    """
    Combine record confidence with source trust and TTL.

    Expired records contribute zero confidence so callers can treat
    them as unknown intelligence.
    """

    if is_expired(expires_at, now=now):
        return 0.0

    return clamp_unit_interval(confidence) * clamp_unit_interval(
        source_confidence
    )


def validate_lifecycle_fields(
    *,
    confidence: float,
    source_confidence: float,
    source: str,
) -> tuple[float, float, str]:
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0.")

    if not 0.0 <= source_confidence <= 1.0:
        raise ValueError(
            "source_confidence must be between 0.0 and 1.0."
        )

    cleaned_source = source.strip() or "ravshield"

    return confidence, source_confidence, cleaned_source
