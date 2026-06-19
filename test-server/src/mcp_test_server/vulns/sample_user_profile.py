from __future__ import annotations

import json

from mcp_test_server.registry import ResourcePlugin


class SampleUserProfile(ResourcePlugin):
    name = "user_profile"
    description = "Fake user profile by id."
    uri_template = "user://profile/{id}"
    mime_type = "application/json"

    async def handle_read(self, id: str) -> str:
        return json.dumps({"id": id, "username": "alice", "email": "alice@example.test"})


PLUGIN = SampleUserProfile()
