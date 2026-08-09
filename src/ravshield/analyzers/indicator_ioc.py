from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.intel import IOCStore, match_ioc
from ravshield.models import DetectionFinding


class IndicatorIOCAnalyzer(BaseAnalyzer):
    """
    Match a string target against an IOC store for a fixed type.

    This adapter lets URL/domain/email/IP pipelines wire IOC matching
    without changing their string target contract.
    """

    def __init__(
        self,
        store: IOCStore | None = None,
        *,
        indicator_type: str,
        name: str | None = None,
    ) -> None:
        self.store = store or IOCStore()
        self.indicator_type = indicator_type.strip().lower()
        self.name = name or f"ioc_{self.indicator_type}"

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        finding = match_ioc(
            self.store,
            self.indicator_type,
            target,
        )

        if finding is None:
            return []

        return [finding]
