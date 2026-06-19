from __future__ import annotations

import logging
import sys
import textwrap
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import MagicMock

import pytest

from mcp_test_server import registry, vulns
from mcp_test_server.registry import (
    ResourcePlugin,
    VulnPlugin,
    discover,
    filter_resource_plugins,
    register_all,
    register_resources_all,
)


class _StubResource(ResourcePlugin):
    name = "stub_res"
    description = "stub resource"
    uri_template = "stub:///{path}"

    async def handle_read(self, **kwargs: Any) -> str:
        return "ok"


class _OtherResource(ResourcePlugin):
    name = "other_res"
    description = "other resource"
    uri_template = "other:///{path}"

    async def handle_read(self, **kwargs: Any) -> str:
        return "other"


class _StubPlugin(VulnPlugin):
    name = "stub"
    description = "stub plugin"
    input_schema: ClassVar[dict[str, Any]] = {"type": "object"}

    async def handle(self, **kwargs: Any) -> str:
        return "ok"


class _OtherPlugin(VulnPlugin):
    name = "other"
    description = "other plugin"
    input_schema: ClassVar[dict[str, Any]] = {"type": "object"}

    async def handle(self, **kwargs: Any) -> str:
        return "other"


def _install_vulns_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    module_name: str,
) -> None:
    module_file = tmp_path / f"{module_name}.py"
    module_file.write_text(textwrap.dedent(body))
    monkeypatch.setattr(vulns, "__path__", [str(tmp_path)])
    fq = f"{vulns.__name__}.{module_name}"
    monkeypatch.delitem(sys.modules, fq, raising=False)


def test_discover_empty_when_no_plugins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vulns, "__path__", [str(tmp_path)])
    assert discover() == []


def test_discover_finds_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = """
        from typing import Any, ClassVar
        from mcp_test_server.registry import VulnPlugin

        class _Discovered(VulnPlugin):
            name = "discovered"
            description = "found me"
            input_schema: ClassVar[dict[str, Any]] = {"type": "object"}

            async def handle(self, **kwargs: Any) -> str:
                return "hit"

        PLUGIN = _Discovered()
    """
    _install_vulns_module(tmp_path, monkeypatch, body, "discovered_plugin")

    plugins = discover()

    assert len(plugins) == 1
    assert plugins[0].name == "discovered"


def test_discover_ignores_private_modules_without_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install_vulns_module(tmp_path, monkeypatch, "X = 1\n", "_helper")

    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        assert discover() == []
    assert not caplog.records


def test_discover_warns_on_public_module_missing_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _install_vulns_module(tmp_path, monkeypatch, "X = 1\n", "forgot_plugin")

    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        assert discover() == []
    assert any("forgot_plugin" in record.message for record in caplog.records)


def test_discover_does_not_warn_when_module_exposes_resource_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    body = """
        from typing import Any
        from mcp_test_server.registry import ResourcePlugin

        class _Resource(ResourcePlugin):
            name = "fake_resource"
            description = "exposes a resource, not a tool"
            uri_template = "file:///{path}"

            async def handle_read(self, **kwargs: Any) -> str:
                return ""

        PLUGIN = _Resource()
    """
    _install_vulns_module(tmp_path, monkeypatch, body, "fake_resource_module")

    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        assert discover() == []
    assert not caplog.records


def test_discover_does_not_warn_when_module_exposes_prompt_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    body = """
        from typing import Any
        from mcp_test_server.registry import PromptPlugin

        class _Prompt(PromptPlugin):
            name = "fake_prompt"
            description = "exposes a prompt, not a tool"

            async def handle_get(self, **kwargs: Any) -> str:
                return ""

        PLUGIN = _Prompt()
    """
    _install_vulns_module(tmp_path, monkeypatch, body, "fake_prompt_module")

    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        assert discover() == []
    assert not caplog.records


def test_register_all_rejects_enabled_and_disabled_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "discover", lambda: [])
    with pytest.raises(ValueError, match="either enabled or disabled"):
        register_all(MagicMock(), enabled={"x"}, disabled={"y"})


def test_register_all_enabled_whitelists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "discover", lambda: [_StubPlugin(), _OtherPlugin()])
    mcp = MagicMock()

    registered = register_all(mcp, enabled={"stub"})

    assert [p.name for p in registered] == ["stub"]
    assert mcp.add_tool.call_count == 1


def test_register_all_disabled_blacklists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "discover", lambda: [_StubPlugin(), _OtherPlugin()])
    mcp = MagicMock()

    registered = register_all(mcp, disabled={"stub"})

    assert [p.name for p in registered] == ["other"]


def test_register_all_calls_add_tool_with_expected_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = _StubPlugin()
    monkeypatch.setattr(registry, "discover", lambda: [plugin])
    mcp = MagicMock()

    register_all(mcp)

    mcp.add_tool.assert_called_once()
    call_args = mcp.add_tool.call_args
    assert call_args.kwargs == {
        "name": "stub",
        "description": "stub plugin",
        "icons": None,
        "annotations": None,
    }
    assert call_args.args[0].__wrapped__ == plugin.handle


def test_vulnplugin_requires_name_and_description() -> None:
    with pytest.raises(TypeError):

        class _MissingAttrs(VulnPlugin):
            async def handle(self, **kwargs: Any) -> str:
                return ""


def test_vulnplugin_input_schema_is_optional() -> None:
    class _NoSchema(VulnPlugin):
        name = "no_schema"
        description = "does not advertise a schema override"

        async def handle(self, **kwargs: Any) -> str:
            return ""

    assert _NoSchema.input_schema is None


def test_vulnplugin_abstract_method_prevents_instantiation() -> None:
    class _MissingHandle(VulnPlugin):
        name = "x"
        description = "x"
        input_schema: ClassVar[dict[str, Any]] = {}

    with pytest.raises(TypeError):
        _MissingHandle()  # type: ignore[abstract]


def test_register_all_registers_plugin_without_input_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoSchemaPlugin(VulnPlugin):
        name = "no_schema_plugin"
        description = "no schema override"

        async def handle(self, **kwargs: Any) -> str:
            return "ok"

    plugin = _NoSchemaPlugin()
    monkeypatch.setattr(registry, "discover", lambda: [plugin])
    mcp = MagicMock()

    registered = register_all(mcp)

    assert [p.name for p in registered] == ["no_schema_plugin"]
    mcp.add_tool.assert_called_once()
    call_args = mcp.add_tool.call_args
    assert call_args.kwargs == {
        "name": "no_schema_plugin",
        "description": "no schema override",
        "icons": None,
        "annotations": None,
    }
    assert call_args.args[0].__wrapped__ == plugin.handle


def test_filter_resource_plugins_rejects_enabled_and_disabled_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry, "discover_resources", lambda: [])
    with pytest.raises(ValueError, match="either enabled or disabled"):
        filter_resource_plugins(enabled={"x"}, disabled={"y"})


def test_register_resources_all_defaults_to_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry, "discover_resources", lambda: [_StubResource(), _OtherResource()]
    )
    mcp = MagicMock()

    registered = register_resources_all(mcp)

    assert {p.name for p in registered} == {"stub_res", "other_res"}


def test_register_resources_all_enabled_whitelists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry, "discover_resources", lambda: [_StubResource(), _OtherResource()]
    )
    mcp = MagicMock()

    registered = register_resources_all(mcp, enabled={"stub_res"})

    assert [p.name for p in registered] == ["stub_res"]


def test_register_resources_all_disabled_blacklists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry, "discover_resources", lambda: [_StubResource(), _OtherResource()]
    )
    mcp = MagicMock()

    registered = register_resources_all(mcp, disabled={"stub_res"})

    assert [p.name for p in registered] == ["other_res"]


def test_register_all_calls_bind_on_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BindingPlugin(VulnPlugin):
        name = "binding"
        description = "records the mcp it was bound to"
        bound_to: Any = None

        async def handle(self, **kwargs: Any) -> str:
            return "ok"

        def bind(self, mcp: Any) -> None:
            self.bound_to = mcp

    plugin = _BindingPlugin()
    monkeypatch.setattr(registry, "discover", lambda: [plugin])
    mcp = MagicMock()

    register_all(mcp)

    assert plugin.bound_to is mcp
