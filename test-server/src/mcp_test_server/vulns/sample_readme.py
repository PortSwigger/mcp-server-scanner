# Sample non-vulnerable resource - populates the scanner UI inventory panel against the test server.
from __future__ import annotations

from mcp_test_server.registry import ResourcePlugin


class SampleReadme(ResourcePlugin):
    name = "readme"
    description = "MCP Server Scanner test-server overview"
    uri_template = "docs://readme"
    mime_type = "text/plain"

    async def handle_read(self) -> str:
        return (
            "MCP test server. Use the registered tools and resources to "
            "exercise scanner checks."
        )


PLUGIN = SampleReadme()
