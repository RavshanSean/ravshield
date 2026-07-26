from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.intel import IOCStore, match_ioc
from ravshield.models import DetectionFinding


class IOCAnalyzer(BaseAnalyzer):
    """
    Match a single typed indicator against an IOCStore.
    """

    name = "ioc"

    def __init__(
        self,
        store: IOCStore | None = None,
    ) -> None:
        self.store = store or IOCStore()

    def analyze(
        self,
        target: tuple[str, str],
    ) -> list[DetectionFinding]:
        indicator_type, value = target

        finding = match_ioc(
            self.store,
            indicator_type,
            value,
        )

        if finding is None:
            return []

        return [finding]