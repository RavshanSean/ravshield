from ravshield.analyzers import BaseAnalyzer
from ravshield.plugins import (
    AnalyzerPlugin,
    PluginLoader,
    PluginMetadata,
)


class DummyAnalyzer(BaseAnalyzer):
    name = "dummy"

    def analyze(self, target):
        return []


def build_plugin(enabled=True):
    return AnalyzerPlugin(
        analyzer=DummyAnalyzer(),
        metadata=PluginMetadata(
            name="Dummy Plugin",
            version="1.0.0",
            description="Plugin used for testing.",
        ),
        enabled=enabled,
    )


def test_plugin_name_is_normalized():
    plugin = build_plugin()

    assert plugin.name == "dummy plugin"


def test_plugin_can_be_disabled():
    plugin = build_plugin()

    plugin.disable()

    assert plugin.enabled is False


def test_plugin_can_be_enabled():
    plugin = build_plugin(enabled=False)

    plugin.enable()

    assert plugin.enabled is True


def test_loader_registers_plugin():
    loader = PluginLoader()

    plugin = build_plugin()

    loader.register(plugin)

    assert len(loader) == 1


def test_loader_returns_enabled_plugins():
    loader = PluginLoader()

    loader.register(build_plugin(enabled=True))
    loader.register(
        AnalyzerPlugin(
            analyzer=DummyAnalyzer(),
            metadata=PluginMetadata(
                name="Disabled",
                version="1.0.0",
                description="Disabled plugin",
            ),
            enabled=False,
        )
    )

    enabled = loader.enabled_plugins()

    assert len(enabled) == 1
    assert enabled[0].name == "dummy plugin"


def test_build_registry_only_uses_enabled_plugins():
    loader = PluginLoader()

    loader.register(build_plugin(enabled=True))
    loader.register(
        AnalyzerPlugin(
            analyzer=DummyAnalyzer(),
            metadata=PluginMetadata(
                name="Disabled",
                version="1.0.0",
                description="Disabled plugin",
            ),
            enabled=False,
        )
    )

    registry = loader.build_registry()

    assert len(registry) == 1