from __future__ import annotations

from mcp_test_server.registry import VulnPlugin


class EvalFormat(VulnPlugin):
    name = "format_quote"
    description = "Render the daily quote via a Python expression."

    # FastMCP infers the tools/list input schema from the handle() signature
    # below; the registry intentionally does not honour plugin-level
    # input_schema overrides, so declaring one here would be dead metadata.

    async def handle(self, format: str) -> str:
        data = {"quote": "Stay hungry, stay foolish.", "author": "Steve Jobs"}
        return str(eval(format, {"data": data, "__builtins__": __builtins__}))


PLUGIN = EvalFormat()
