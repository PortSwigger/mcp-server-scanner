# Sample non-vulnerable resource - populates the scanner UI inventory panel against the test server.
from __future__ import annotations

from mcp_test_server.registry import ResourcePlugin


class SampleUsers(ResourcePlugin):
    name = "users_sample"
    description = "Sample user records"
    uri_template = "data://users/sample"
    mime_type = "application/json"

    async def handle_read(self) -> str:
        return '[{"id":1,"username":"alice"},{"id":2,"username":"bob"}]'


PLUGIN = SampleUsers()
