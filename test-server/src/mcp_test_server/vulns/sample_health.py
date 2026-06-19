# Sample non-vulnerable resource - populates the scanner UI inventory panel against the test server.
from __future__ import annotations

from mcp_test_server.registry import ResourcePlugin


class SampleHealth(ResourcePlugin):
    name = "health"
    description = "Service health snapshot"
    uri_template = "status://health"
    mime_type = "application/json"

    async def handle_read(self) -> str:
        return '{"ok":true,"uptime":"3d"}'


PLUGIN = SampleHealth()
