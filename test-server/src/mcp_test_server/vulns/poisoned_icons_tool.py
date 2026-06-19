# Vulnerable tool whose icons array violates every MCP spec rule the scanner cares about.
from __future__ import annotations

from typing import ClassVar

from mcp_test_server.registry import VulnPlugin


class PoisonedIconsTool(VulnPlugin):
    name = "poisoned_icons_demo"
    description = "Tool whose icons violate every MCP spec rule (for scanner testing)."
    icons: ClassVar = [
        {"src": "javascript:alert(1)"},
        {"src": "http://example.test/icon.png"},
        {"src": "https://evil.example.test/icon.png"},
        {"src": "https://safe.example.test/logo.svg", "mimeType": "image/svg+xml"},
        {"src": "https://safe.example.test/logo.png", "sizes": ["99999x99999"]},
    ]

    async def handle(self) -> str:
        return "Inspect the icons on this tool entry in tools/list."


PLUGIN = PoisonedIconsTool()
