from __future__ import annotations

from ravshield.analyzers.domain import DomainReputationAnalyzer
from ravshield.analyzers.domain_heuristics import DomainHeuristicAnalyzer
from ravshield.analyzers.email import EmailReputationAnalyzer
from ravshield.analyzers.email_heuristics import EmailHeuristicAnalyzer
from ravshield.analyzers.pipeline import ScanPipeline
from ravshield.analyzers.url import URLAnalyzer
from ravshield.analyzers.url_heuristics import URLHeuristicAnalyzer
from ravshield.intel.domain import DomainReputationService
from ravshield.intel.email import EmailReputationService
from ravshield.intel.url import URLReputationService


def create_domain_pipeline(
    reputation_service: DomainReputationService | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for domain analysis.

    The pipeline includes:

    - Domain reputation analysis
    - Domain heuristic analysis
    """

    pipeline = ScanPipeline()

    pipeline.register(
        DomainReputationAnalyzer(reputation_service)
    )
    pipeline.register(
        DomainHeuristicAnalyzer()
    )

    return pipeline


def create_email_pipeline(
    reputation_service: EmailReputationService | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for email analysis.

    The pipeline includes:

    - Email reputation analysis
    - Email heuristic analysis
    """

    pipeline = ScanPipeline()

    pipeline.register(
        EmailReputationAnalyzer(
            reputation_service
        )
    )

    pipeline.register(
        EmailHeuristicAnalyzer()
    )

    return pipeline

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

    pipeline.register(URLAnalyzer(reputation_service))
    pipeline.register(URLHeuristicAnalyzer())

    return pipeline