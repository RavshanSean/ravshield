from __future__ import annotations

from ravshield.analyzers.pipeline import ScanPipeline
from ravshield.analyzers.url import URLAnalyzer
from ravshield.analyzers.url_heuristics import URLHeuristicAnalyzer
from ravshield.intel.url import URLReputationService


def create_url_pipeline(
    reputation_service: URLReputationService | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for URL analysis.

    The pipeline includes:

    - URL reputation analysis
    - URL heuristic analysis
    """

    pipeline = ScanPipeline()

    pipeline.register(
        URLAnalyzer(reputation_service)
    )
    pipeline.register(
        URLHeuristicAnalyzer()
    )

    return pipeline