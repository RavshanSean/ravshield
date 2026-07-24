from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ravshield.analyzers import BaseAnalyzer


@dataclass(slots=True, frozen=True)
class PluginMetadata:
    """
    Describes a RavShield analyzer plugin.

    Metadata helps RavShield identify, validate,
    display, and manage external analyzers.
    """

    name: str
    version: str
    description: str
    author: str | None = None
    homepage: str | None = None
    enabled_by_default: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Plugin name cannot be empty.")

        if not self.version.strip():
            raise ValueError("Plugin version cannot be empty.")

        if not self.description.strip():
            raise ValueError(
                "Plugin description cannot be empty."
            )


class AnalyzerPlugin:
    """
    Wraps an analyzer together with plugin metadata
    and optional configuration.
    """

    def __init__(
        self,
        analyzer: BaseAnalyzer,
        metadata: PluginMetadata,
        *,
        config: dict[str, Any] | None = None,
        enabled: bool | None = None,
    ) -> None:
        if not isinstance(analyzer, BaseAnalyzer):
            raise TypeError(
                "Plugin analyzer must inherit from BaseAnalyzer."
            )

        self.analyzer = analyzer
        self.metadata = metadata
        self.config = dict(config or {})

        self.enabled = (
            metadata.enabled_by_default
            if enabled is None
            else enabled
        )

    @property
    def name(self) -> str:
        return self.metadata.name.strip().lower()

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def update_config(
        self,
        **settings: Any,
    ) -> None:
        self.config.update(settings)