from __future__ import annotations

from collections.abc import Iterable

from ravshield.analyzers.base import BaseAnalyzer


class AnalyzerRegistry:
    """
    Stores and manages RavShield analyzers.

    The registry allows analyzers to be added, removed,
    discovered, and executed by the scan pipeline.
    """

    def __init__(
        self,
        analyzers: Iterable[BaseAnalyzer] | None = None,
    ) -> None:
        self._analyzers: dict[str, BaseAnalyzer] = {}

        if analyzers is not None:
            for analyzer in analyzers:
                self.register(analyzer)

    def register(
        self,
        analyzer: BaseAnalyzer,
        *,
        replace: bool = False,
    ) -> None:
        """
        Register an analyzer instance.

        Parameters
        ----------
        analyzer:
            Analyzer instance to register.

        replace:
            Whether an existing analyzer with the same
            name may be replaced.
        """
        name = self._validate_name(analyzer)

        if name in self._analyzers and not replace:
            raise ValueError(
                f"Analyzer '{name}' is already registered."
            )

        self._analyzers[name] = analyzer

    def unregister(self, name: str) -> BaseAnalyzer:
        """
        Remove and return an analyzer by name.
        """
        normalized_name = self._normalize_name(name)

        try:
            return self._analyzers.pop(normalized_name)
        except KeyError as error:
            raise KeyError(
                f"Analyzer '{normalized_name}' is not registered."
            ) from error

    def get(self, name: str) -> BaseAnalyzer:
        """
        Return a registered analyzer by name.
        """
        normalized_name = self._normalize_name(name)

        try:
            return self._analyzers[normalized_name]
        except KeyError as error:
            raise KeyError(
                f"Analyzer '{normalized_name}' is not registered."
            ) from error

    def contains(self, name: str) -> bool:
        """
        Check whether an analyzer is registered.
        """
        return self._normalize_name(name) in self._analyzers

    def names(self) -> list[str]:
        """
        Return analyzer names in registration order.
        """
        return list(self._analyzers)

    def all(self) -> list[BaseAnalyzer]:
        """
        Return all registered analyzer instances.
        """
        return list(self._analyzers.values())

    def clear(self) -> None:
        """
        Remove all registered analyzers.
        """
        self._analyzers.clear()

    def __len__(self) -> int:
        return len(self._analyzers)

    def __iter__(self):
        return iter(self._analyzers.values())

    @staticmethod
    def _normalize_name(name: str) -> str:
        normalized_name = name.strip().lower()

        if not normalized_name:
            raise ValueError("Analyzer name cannot be empty.")

        return normalized_name

    def _validate_name(
        self,
        analyzer: BaseAnalyzer,
    ) -> str:
        if not isinstance(analyzer, BaseAnalyzer):
            raise TypeError(
                "Analyzer must inherit from BaseAnalyzer."
            )

        return self._normalize_name(analyzer.name)