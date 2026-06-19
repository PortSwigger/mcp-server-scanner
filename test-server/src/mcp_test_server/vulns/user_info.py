from __future__ import annotations

from mcp_test_server.registry import VulnPlugin

_PROFILE = (
    "name: Alice Example\n"
    "email: alice@example.internal\n"
    "phone: +1-415-555-0142\n"
    "card: 4111 1111 1111 1111\n"
    "internal_host: 10.0.13.37\n"
)


class UserInfo(VulnPlugin):
    name = "user_info"
    description = "Return profile details for the current user."
    annotations = {"readOnlyHint": True}

    async def handle(self, username: str = "alice") -> str:
        return _PROFILE


PLUGIN = UserInfo()
