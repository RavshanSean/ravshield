from __future__ import annotations

from ravshield.analyzers.domain import DomainReputationAnalyzer
from ravshield.analyzers.domain_heuristics import DomainHeuristicAnalyzer
from ravshield.analyzers.email import EmailReputationAnalyzer
from ravshield.analyzers.email_auth import EmailAuthAnalyzer
from ravshield.analyzers.email_heuristics import EmailHeuristicAnalyzer
from ravshield.analyzers.file_hash import FileHashAnalyzer, HashIOCAnalyzer
from ravshield.analyzers.indicator_ioc import IndicatorIOCAnalyzer
from ravshield.analyzers.ip import IPReputationAnalyzer
from ravshield.analyzers.ip_heuristics import IPHeuristicAnalyzer
from ravshield.analyzers.pipeline import ScanPipeline
from ravshield.analyzers.url import URLAnalyzer
from ravshield.analyzers.url_heuristics import URLHeuristicAnalyzer
from ravshield.intel import IOCStore
from ravshield.intel.domain import DomainReputationService
from ravshield.intel.email import EmailReputationService
from ravshield.intel.ip import IPReputationService
from ravshield.intel.url import URLReputationService


def create_domain_pipeline(
    reputation_service: DomainReputationService | None = None,
    *,
    ioc_store: IOCStore | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for domain analysis.

    The pipeline includes:

    - Domain reputation analysis
    - Domain heuristic analysis
    - Optional IOC matching
    """

    pipeline = ScanPipeline()

    pipeline.register(
        DomainReputationAnalyzer(reputation_service)
    )
    pipeline.register(
        DomainHeuristicAnalyzer()
    )

    if ioc_store is not None:
        pipeline.register(
            IndicatorIOCAnalyzer(
                ioc_store,
                indicator_type="domain",
            )
        )

    return pipeline


def create_email_pipeline(
    reputation_service: EmailReputationService | None = None,
    *,
    ioc_store: IOCStore | None = None,
    include_auth_headers: bool = True,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for email analysis.

    The pipeline includes:

    - Email reputation analysis
    - Email heuristic analysis
    - Optional SPF/DKIM/DMARC header analysis
    - Optional IOC matching
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

    if include_auth_headers:
        pipeline.register(EmailAuthAnalyzer())

    if ioc_store is not None:
        pipeline.register(
            IndicatorIOCAnalyzer(
                ioc_store,
                indicator_type="email",
            )
        )

    return pipeline


def create_url_pipeline(
    reputation_service: URLReputationService | None = None,
    *,
    ioc_store: IOCStore | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for URL analysis.

    The pipeline includes:

    - URL reputation analysis
    - URL heuristic analysis
    - Optional IOC matching
    """

    pipeline = ScanPipeline()

    pipeline.register(URLAnalyzer(reputation_service))
    pipeline.register(URLHeuristicAnalyzer())

    if ioc_store is not None:
        pipeline.register(
            IndicatorIOCAnalyzer(
                ioc_store,
                indicator_type="url",
            )
        )

    return pipeline


def create_ip_pipeline(
    reputation_service: IPReputationService | None = None,
    *,
    ioc_store: IOCStore | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline configured for IP analysis.

    The pipeline includes:

    - IP reputation analysis
    - IP heuristic / scope classification
    - Optional IOC matching
    """

    pipeline = ScanPipeline()

    pipeline.register(
        IPReputationAnalyzer(reputation_service)
    )
    pipeline.register(IPHeuristicAnalyzer())

    if ioc_store is not None:
        pipeline.register(
            IndicatorIOCAnalyzer(
                ioc_store,
                indicator_type="ip",
            )
        )

    return pipeline


def create_file_pipeline(
    *,
    ioc_store: IOCStore | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline for local file hash malware checks.
    """

    pipeline = ScanPipeline()
    pipeline.register(FileHashAnalyzer(ioc_store))
    return pipeline


def create_hash_pipeline(
    *,
    ioc_store: IOCStore | None = None,
) -> ScanPipeline:
    """
    Create a ScanPipeline for raw hash string reputation/IOC checks.
    """

    pipeline = ScanPipeline()
    pipeline.register(HashIOCAnalyzer(ioc_store))
    return pipeline
