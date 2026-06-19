# Vulnerable resource whose icons array violates the MCP spec's client-side rejection rules.
from __future__ import annotations

from typing import ClassVar

from mcp_test_server.registry import ResourcePlugin


class PoisonedIconsResource(ResourcePlugin):
    name = "poisoned_icons_resource"
    description = "Resource whose icons violate MCP spec icon rules (for scanner testing)."
    uri_template = "poisoned://icons-resource"
    mime_type = "text/plain"
    icons: ClassVar = [
        {"src": "javascript:alert(1)"},
        {"src": "http://example.test/resource-icon.png"},
        {"src": "https://evil.example.test/resource-icon.png"},
        {"src": "https://safe.example.test/resource-icon.svg", "mimeType": "image/svg+xml"},
        {"src": "https://safe.example.test/resource-icon.png", "sizes": ["99999x99999"]},
    ]

    async def handle_read(self) -> str:
        return "Inspect the icons on this resource entry in resources/list."


PLUGIN = PoisonedIconsResource()
