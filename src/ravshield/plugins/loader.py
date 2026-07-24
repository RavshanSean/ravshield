from __future__ import annotations

from collections.abc import Iterable

from ravshield.analyzers import AnalyzerRegistry
from ravshield.plugins.plugin import AnalyzerPlugin


class PluginLoader:
    """
    Loads RavShield plugins into an AnalyzerRegistry.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, AnalyzerPlugin] = {}

    def register(
        self,
        plugin: AnalyzerPlugin,
        *,
        replace: bool = False,
    ) -> None:
        name = plugin.name

        if name in self._plugins and not replace:
            raise ValueError(
                f"Plugin '{name}' is already registered."
            )

        self._plugins[name] = plugin

    def unregister(
        self,
        name: str,
    ) -> AnalyzerPlugin:
        try:
            return self._plugins.pop(name.lower())
        except KeyError as error:
            raise KeyError(
                f"Plugin '{name}' is not registered."
            ) from error

    def get(
        self,
        name: str,
    ) -> AnalyzerPlugin:
        try:
            return self._plugins[name.lower()]
        except KeyError as error:
            raise KeyError(
                f"Plugin '{name}' is not registered."
            ) from error

    def plugins(self) -> list[AnalyzerPlugin]:
        return list(self._plugins.values())

    def enabled_plugins(self) -> list[AnalyzerPlugin]:
        return [
            plugin
            for plugin in self._plugins.values()
            if plugin.enabled
        ]

    def build_registry(self) -> AnalyzerRegistry:
        """
        Create an AnalyzerRegistry using only
        enabled plugins.
        """

        registry = AnalyzerRegistry()

        for plugin in self.enabled_plugins():
            registry.register(plugin.analyzer)

        return registry

    def clear(self) -> None:
        self._plugins.clear()

    def __len__(self) -> int:
        return len(self._plugins)

    def __iter__(self):
        return iter(self._plugins.values())

    @classmethod
    def from_plugins(
        cls,
        plugins: Iterable[AnalyzerPlugin],
    ) -> "PluginLoader":
        loader = cls()

        for plugin in plugins:
            loader.register(plugin)

        return loader