from __future__ import annotations

from abc import ABC, abstractmethod

from ravshield.models import DetectionFinding


class BaseAnalyzer(ABC):
    """
    Base class for every RavShield analyzer.

    Every analyzer receives some input,
    performs its own analysis,
    and returns DetectionFinding objects.
    """

    name = "base"

    @abstractmethod
    def analyze(self, target) -> list[DetectionFinding]:
        """
        Analyze a target.

        Parameters
        ----------
        target:
            Any object the analyzer understands.

        Returns
        -------
        list[DetectionFinding]
            Findings produced by this analyzer.
        """
        raise NotImplementedError