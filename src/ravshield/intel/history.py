from dataclasses import dataclass, field
from datetime import datetime, timezone

from ravshield.enums import Verdict
from ravshield.intel.ioc import (
    is_valid_indicator,
    normalize_indicator_type,
    normalize_indicator_value,
)


@dataclass(slots=True)
class IndicatorHistory:
    indicator_type: str
    value: str
    first_seen: datetime
    last_seen: datetime
    observation_count: int = 1
    sources: set[str] = field(default_factory=set)
    verdict_history: list[Verdict] = field(default_factory=list)

    def __post_init__(self) -> None:
        normalized_type = normalize_indicator_type(
            self.indicator_type
        )

        if not is_valid_indicator(
            normalized_type,
            self.value,
        ):
            raise ValueError(
                f"Invalid {normalized_type} indicator: {self.value}"
            )

        if self.first_seen.tzinfo is None:
            raise ValueError(
                "first_seen must include timezone information."
            )

        if self.last_seen.tzinfo is None:
            raise ValueError(
                "last_seen must include timezone information."
            )

        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen cannot be earlier than first_seen."
            )

        if self.observation_count < 1:
            raise ValueError(
                "observation_count must be at least 1."
            )

        self.indicator_type = normalized_type
        self.value = normalize_indicator_value(
            normalized_type,
            self.value,
        )

        self.sources = {
            source.strip()
            for source in self.sources
            if source.strip()
        }

    def record_observation(
        self,
        *,
        source: str,
        verdict: Verdict,
        observed_at: datetime | None = None,
    ) -> None:
        timestamp = observed_at or datetime.now(timezone.utc)

        if timestamp.tzinfo is None:
            raise ValueError(
                "observed_at must include timezone information."
            )

        if timestamp < self.first_seen:
            self.first_seen = timestamp

        if timestamp > self.last_seen:
            self.last_seen = timestamp

        self.observation_count += 1

        normalized_source = source.strip()

        if normalized_source:
            self.sources.add(normalized_source)

        self.verdict_history.append(verdict)


class DetectionHistoryStore:
    def __init__(self) -> None:
        self._records: dict[
            tuple[str, str],
            IndicatorHistory,
        ] = {}

    @staticmethod
    def _build_key(
        indicator_type: str,
        value: str,
    ) -> tuple[str, str]:
        normalized_type = normalize_indicator_type(
            indicator_type
        )

        normalized_value = normalize_indicator_value(
            normalized_type,
            value,
        )

        return normalized_type, normalized_value

    def observe(
        self,
        indicator_type: str,
        value: str,
        *,
        source: str,
        verdict: Verdict,
        observed_at: datetime | None = None,
    ) -> IndicatorHistory:
        timestamp = observed_at or datetime.now(timezone.utc)

        key = self._build_key(
            indicator_type,
            value,
        )

        existing = self._records.get(key)

        if existing is not None:
            existing.record_observation(
                source=source,
                verdict=verdict,
                observed_at=timestamp,
            )

            return existing

        history = IndicatorHistory(
            indicator_type=indicator_type,
            value=value,
            first_seen=timestamp,
            last_seen=timestamp,
            observation_count=1,
            sources={source},
            verdict_history=[verdict],
        )

        self._records[key] = history

        return history

    def get(
        self,
        indicator_type: str,
        value: str,
    ) -> IndicatorHistory | None:
        try:
            key = self._build_key(
                indicator_type,
                value,
            )
        except ValueError:
            return None

        return self._records.get(key)

    def remove(
        self,
        indicator_type: str,
        value: str,
    ) -> bool:
        try:
            key = self._build_key(
                indicator_type,
                value,
            )
        except ValueError:
            return False

        return self._records.pop(key, None) is not None

    def all(self) -> list[IndicatorHistory]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)