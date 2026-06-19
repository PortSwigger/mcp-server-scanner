from __future__ import annotations

from mcp_test_server.registry import PromptPlugin


class SampleSummarize(PromptPlugin):
    name = "summarize"
    description = "Summarise a block of text in one paragraph."

    async def handle_get(self, text: str) -> str:
        return f"Summarise the following text in one paragraph:\n\n{text}"


PLUGIN = SampleSummarize()
