from __future__ import annotations

import functools
import importlib
import logging
import pkgutil
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Collection, Iterator
from types import ModuleType
from typing import TYPE_CHECKING, Any, ClassVar

from mcp_test_server import vulns

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

_REQUIRED_ATTRS = ("name", "description")
_REQUIRED_RESOURCE_ATTRS = ("name", "description", "uri_template")
_REQUIRED_PROMPT_ATTRS = ("name", "description")


class VulnPlugin(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    input_schema: ClassVar[dict[str, Any] | None] = None
    icons: ClassVar[list[dict[str, Any]] | None] = None
    annotations: ClassVar[dict[str, Any] | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", None):
            return
        missing = [attr for attr in _REQUIRED_ATTRS if not hasattr(cls, attr)]
        if missing:
            raise TypeError(
                f"{cls.__name__} is missing required class attributes: {', '.join(missing)}"
            )

    @abstractmethod
    async def handle(self, *args: Any, **kwargs: Any) -> str: ...

    def bind(self, mcp: FastMCP) -> None:
        pass


class ResourcePlugin(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    uri_template: ClassVar[str]
    mime_type: ClassVar[str] = "text/plain"
    icons: ClassVar[list[dict[str, Any]] | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", None):
            return
        missing = [attr for attr in _REQUIRED_RESOURCE_ATTRS if not hasattr(cls, attr)]
        if missing:
            raise TypeError(
                f"{cls.__name__} is missing required class attributes: {', '.join(missing)}"
            )

    @abstractmethod
    async def handle_read(self, *args: Any, **kwargs: Any) -> str: ...

    def concrete_uri(self) -> str | None:
        """Optional concrete (no-{var}) resource URI to advertise in resources/list.

        Lets a fixture leak its real filesystem root so a remote check can derive a
        sandbox boundary (e.g. the CVE-2025-53110 prefix-sibling probe). Returns None
        by default (template-only resource).
        """
        return None

    async def handle_concrete(self) -> str:
        """Read handler for the optional concrete_uri advertisement."""
        return "in-root canary"


class PromptPlugin(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    icons: ClassVar[list[dict[str, Any]] | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "__abstractmethods__", None):
            return
        missing = [attr for attr in _REQUIRED_PROMPT_ATTRS if not hasattr(cls, attr)]
        if missing:
            raise TypeError(
                f"{cls.__name__} is missing required class attributes: {', '.join(missing)}"
            )

    @abstractmethod
    async def handle_get(self, *args: Any, **kwargs: Any) -> str: ...


def _iter_plugin_modules() -> Iterator[tuple[pkgutil.ModuleInfo, ModuleType, Any]]:
    for module_info in pkgutil.iter_modules(vulns.__path__):
        module = importlib.import_module(f"{vulns.__name__}.{module_info.name}")
        plugin = getattr(module, "PLUGIN", None)
        yield module_info, module, plugin


def discover() -> list[VulnPlugin]:
    plugins: list[VulnPlugin] = []
    for module_info, _module, plugin in _iter_plugin_modules():
        if isinstance(plugin, VulnPlugin):
            plugins.append(plugin)
        elif isinstance(plugin, (ResourcePlugin, PromptPlugin)):
            continue
        elif not module_info.name.startswith("_"):
            logger.warning("Module %s has no PLUGIN attribute; skipping", module_info.name)
    return plugins


def discover_resources() -> list[ResourcePlugin]:
    return [plugin for _, _, plugin in _iter_plugin_modules() if isinstance(plugin, ResourcePlugin)]


def discover_prompts() -> list[PromptPlugin]:
    return [plugin for _, _, plugin in _iter_plugin_modules() if isinstance(plugin, PromptPlugin)]


def filter_plugins(
    enabled: Collection[str] | None = None,
    disabled: Collection[str] | None = None,
) -> list[VulnPlugin]:
    if enabled is not None and disabled is not None:
        raise ValueError("Specify either enabled or disabled, not both")
    selected: list[VulnPlugin] = []
    for plugin in discover():
        if enabled is not None and plugin.name not in enabled:
            continue
        if disabled is not None and plugin.name in disabled:
            continue
        selected.append(plugin)
    return selected


def register_all(
    mcp: FastMCP,
    enabled: Collection[str] | None = None,
    disabled: Collection[str] | None = None,
) -> list[VulnPlugin]:
    plugins = filter_plugins(enabled=enabled, disabled=disabled)
    for plugin in plugins:
        # Note: plugin.input_schema override is intentionally not honoured; FastMCP infers the schema from the handler signature.
        mcp.add_tool(
            _instrument(plugin),
            name=plugin.name,
            description=plugin.description,
            icons=plugin.icons,
            annotations=plugin.annotations,
        )
        plugin.bind(mcp)
    return plugins


def filter_resource_plugins(
    enabled: Collection[str] | None = None,
    disabled: Collection[str] | None = None,
) -> list[ResourcePlugin]:
    if enabled is not None and disabled is not None:
        raise ValueError("Specify either enabled or disabled, not both")
    selected: list[ResourcePlugin] = []
    for plugin in discover_resources():
        if enabled is not None and plugin.name not in enabled:
            continue
        if disabled is not None and plugin.name in disabled:
            continue
        selected.append(plugin)
    return selected


def register_resources_all(
    mcp: FastMCP,
    enabled: Collection[str] | None = None,
    disabled: Collection[str] | None = None,
) -> list[ResourcePlugin]:
    plugins = filter_resource_plugins(enabled=enabled, disabled=disabled)
    for plugin in plugins:
        mcp.resource(
            plugin.uri_template,
            name=plugin.name,
            description=plugin.description,
            mime_type=plugin.mime_type,
            icons=plugin.icons,
        )(_instrument_resource(plugin))
        concrete = plugin.concrete_uri()
        if concrete is not None:
            mcp.resource(
                concrete,
                name=f"{plugin.name}_root",
                description=f"{plugin.description} (root marker)",
                mime_type=plugin.mime_type,
            )(_instrument_handler(
                "resource", f"{plugin.name}_root", plugin.handle_concrete, log_preview=False,
            ))
    return plugins


def register_prompts_all(mcp: FastMCP) -> list[PromptPlugin]:
    plugins = discover_prompts()
    for plugin in plugins:
        # FastMCP infers prompt argument metadata from the wrapped handler's signature.
        mcp.prompt(
            name=plugin.name,
            description=plugin.description,
            icons=plugin.icons,
        )(_instrument_prompt(plugin))
    return plugins


def _instrument_handler(
    label: str,
    plugin_name: str,
    handler: Callable[..., Awaitable[str]],
    *,
    log_preview: bool,
) -> Callable[..., Awaitable[str]]:
    @functools.wraps(handler)
    async def wrapped(*args: Any, **kwargs: Any) -> str:
        start = time.monotonic()
        logger.info("%s=%s args=%s", label, plugin_name, kwargs)
        try:
            result = await handler(*args, **kwargs)
        except Exception:
            duration_ms = (time.monotonic() - start) * 1000
            logger.exception("%s=%s FAILED after %.0fms", label, plugin_name, duration_ms)
            raise
        duration_ms = (time.monotonic() - start) * 1000
        if log_preview:
            preview = result[:200].replace("\n", "\\n")
            logger.info(
                "%s=%s done in %.0fms bytes=%d preview=%r",
                label,
                plugin_name,
                duration_ms,
                len(result),
                preview,
            )
        else:
            logger.info(
                "%s=%s done in %.0fms bytes=%d",
                label,
                plugin_name,
                duration_ms,
                len(result),
            )
        return result

    return wrapped


def _instrument(plugin: VulnPlugin) -> Callable[..., Awaitable[str]]:
    return _instrument_handler("tool", plugin.name, plugin.handle, log_preview=True)


def _instrument_resource(plugin: ResourcePlugin) -> Callable[..., Awaitable[str]]:
    return _instrument_handler("resource", plugin.name, plugin.handle_read, log_preview=False)


def _instrument_prompt(plugin: PromptPlugin) -> Callable[..., Awaitable[str]]:
    return _instrument_handler("prompt", plugin.name, plugin.handle_get, log_preview=False)
