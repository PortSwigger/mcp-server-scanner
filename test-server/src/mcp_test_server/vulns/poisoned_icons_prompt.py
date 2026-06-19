# Vulnerable prompt whose icons array violates the MCP spec's client-side rejection rules.
from __future__ import annotations

from typing import ClassVar

from mcp_test_server.registry import PromptPlugin


class PoisonedIconsPrompt(PromptPlugin):
    name = "poisoned_icons_prompt"
    description = "Prompt whose icons violate MCP spec icon rules (for scanner testing)."
    icons: ClassVar = [
        {"src": "javascript:alert(1)"},
        {"src": "http://example.test/prompt-icon.png"},
        {"src": "https://evil.example.test/prompt-icon.png"},
        {"src": "https://safe.example.test/prompt-icon.svg", "mimeType": "image/svg+xml"},
        {"src": "https://safe.example.test/prompt-icon.png", "sizes": ["99999x99999"]},
    ]

    async def handle_get(self) -> str:
        return "Inspect the icons on this prompt entry in prompts/list."


PLUGIN = PoisonedIconsPrompt()
