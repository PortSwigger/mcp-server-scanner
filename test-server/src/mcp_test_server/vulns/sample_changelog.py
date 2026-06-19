# Sample non-vulnerable resource - populates the scanner UI inventory panel against the test server.
from __future__ import annotations

from mcp_test_server.registry import ResourcePlugin


class SampleChangelog(ResourcePlugin):
    name = "changelog"
    description = "Fixture changelog"
    uri_template = "docs://changelog"
    mime_type = "text/plain"

    async def handle_read(self) -> str:
        return (
            "- 0.1.0-vuln-fixture: initial vulnerable-by-design release\n"
            "- 0.1.0-vuln-fixture: hidden methods bypass auth middleware\n"
            "- 0.1.0-vuln-fixture: OAuth strategy added with togglable checks"
        )


PLUGIN = SampleChangelog()
