from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.enums import Severity
from ravshield.models import DetectionFinding
from ravshield.plugins.plugin import AnalyzerPlugin, PluginMetadata


@dataclass(slots=True)
class EnrichmentResult:
    """
    Optional enrichment output produced by an offline/online enricher.
    """

    signals: set[str] = field(default_factory=set)
    details: dict[str, Any] = field(default_factory=dict)
    findings: list[DetectionFinding] = field(default_factory=list)


class Enricher(Protocol):
    """
    Contract for DNS / WHOIS / ASN / passive-DNS style enrichers.

    Implementations may perform network I/O. Core RavShield remains
    offline; enrichers are opt-in plugins.
    """

    name: str

    def enrich(
        self,
        indicator_type: str,
        value: str,
    ) -> EnrichmentResult:
        ...


class StaticMapEnricher:
    """
    Offline enricher backed by a local mapping.

    Useful for ASN / org labels without outbound network calls.
    """

    def __init__(
        self,
        name: str,
        mapping: dict[str, dict[str, Any]],
        *,
        indicator_type: str = "ip",
        malicious_tags: set[str] | None = None,
    ) -> None:
        self.name = name
        self.mapping = {
            key.lower(): value
            for key, value in mapping.items()
        }
        self.indicator_type = indicator_type
        self.malicious_tags = malicious_tags or {
            "tor",
            "c2",
            "scanner",
            "botnet",
        }

    def enrich(
        self,
        indicator_type: str,
        value: str,
    ) -> EnrichmentResult:
        if indicator_type != self.indicator_type:
            return EnrichmentResult()

        record = self.mapping.get(value.lower())

        if record is None:
            return EnrichmentResult()

        signals: set[str] = set()
        tags = {
            str(tag).lower()
            for tag in record.get("tags", [])
        }

        if tags & self.malicious_tags:
            signals.add("enrichment_malicious_tag")

        findings: list[DetectionFinding] = []

        if "enrichment_malicious_tag" in signals:
            findings.append(
                DetectionFinding(
                    code="ENRICHMENT_MALICIOUS_TAG",
                    title="Enrichment malicious tag",
                    description=(
                        "Local enrichment data tagged this indicator "
                        "with a high-risk category."
                    ),
                    severity=Severity.HIGH,
                    confidence=80,
                    evidence={
                        "enricher": self.name,
                        "indicator_type": indicator_type,
                        "value": value,
                        "tags": sorted(tags),
                        **{
                            key: record[key]
                            for key in record
                            if key != "tags"
                        },
                    },
                )
            )

        return EnrichmentResult(
            signals=signals,
            details={
                "enricher": self.name,
                **record,
            },
            findings=findings,
        )


class EnrichmentAnalyzer(BaseAnalyzer):
    """
    Run registered enrichers against a typed indicator target.

    Target shapes:
    - ``(indicator_type, value)``
    - ``{"type": "...", "value": "..."}``
    """

    name = "enrichment"

    def __init__(
        self,
        enrichers: list[Enricher] | None = None,
    ) -> None:
        self.enrichers = list(enrichers or [])

    def analyze(
        self,
        target: Any,
    ) -> list[DetectionFinding]:
        indicator_type, value = self._parse_target(target)
        findings: list[DetectionFinding] = []

        for enricher in self.enrichers:
            result = enricher.enrich(indicator_type, value)
            findings.extend(result.findings)

        return findings

    @staticmethod
    def _parse_target(target: Any) -> tuple[str, str]:
        if (
            isinstance(target, tuple)
            and len(target) == 2
        ):
            return str(target[0]), str(target[1])

        if isinstance(target, dict):
            return (
                str(target["type"]),
                str(target["value"]),
            )

        raise TypeError(
            "EnrichmentAnalyzer target must be "
            "(indicator_type, value) or "
            "{'type': ..., 'value': ...}."
        )


def enrichment_plugin(
    enricher: Enricher,
    *,
    version: str = "0.1.0",
    description: str | None = None,
) -> AnalyzerPlugin:
    """
    Wrap a single enricher as an AnalyzerPlugin.
    """

    analyzer = EnrichmentAnalyzer([enricher])

    return AnalyzerPlugin(
        analyzer=analyzer,
        metadata=PluginMetadata(
            name=f"enrichment-{enricher.name}",
            version=version,
            description=(
                description
                or f"Enrichment plugin for {enricher.name}"
            ),
            tags=("enrichment",),
        ),
    )
