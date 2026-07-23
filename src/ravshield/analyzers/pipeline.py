from __future__ import annotations

from ravshield.analyzers.registry import AnalyzerRegistry
from ravshield.engines import MultiSignalVerdictEngine
from ravshield.models import AnalysisResult, DetectionFinding


class ScanPipeline:
    """
    Executes registered analyzers and combines
    their findings into a final AnalysisResult.
    """

    def __init__(
        self,
        registry: AnalyzerRegistry | None = None,
        verdict_engine: MultiSignalVerdictEngine | None = None,
    ) -> None:
        self.registry = registry or AnalyzerRegistry()
        self.verdict_engine = (
            verdict_engine or MultiSignalVerdictEngine()
        )

    def analyze(self, target) -> AnalysisResult:
        """
        Run every registered analyzer against
        the supplied target.
        """

        findings: list[DetectionFinding] = []
        executed_modules: list[str] = []

        for analyzer in self.registry:
            analyzer_findings = analyzer.analyze(target)

            findings.extend(analyzer_findings)
            executed_modules.append(analyzer.name)

        return self.verdict_engine.analyze(
            findings,
            analysis_modules=executed_modules,
        )