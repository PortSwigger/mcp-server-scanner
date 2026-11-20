from __future__ import annotations

from typing import Any

from mcp_test_server.identity.access import Access
from mcp_test_server.identity.users import IdentityWeakness, Role, User, UserDirectory
from mcp_test_server.protocol.catalog import Arguments, Tool, text_content
from mcp_test_server.protocol.context import CallContext
from mcp_test_server.protocol.jsonrpc import JsonObject
from mcp_test_server.surface import ServerSurface
from mcp_test_server.vulns.weakness_vulnerability import WeaknessVulnerability
from mcp_test_server.weakness import WeaknessSet

DELETE_USER_SCHEMA = {"type": "object", "properties": {"username": {"type": "string"}}, "required": ["username"]}


class AuthUnknownTokenServiceAccount(WeaknessVulnerability):
    name = "auth_unknown_token_service_account"
    summary = ("An unrecognised bearer token falls back to a privileged service account that lists and calls the "
               "admin tools list_users and delete_user (the PraisonAI CVE-2026-34953 shape)")
    weakness = IdentityWeakness.UNKNOWN_TOKEN_SERVICE_ACCOUNT

    def weakness_set(self, surface: ServerSurface) -> WeaknessSet[Any]:
        return surface.identity_weaknesses

    def contribute(self, surface: ServerSurface) -> None:
        super().contribute(surface)
        self._users = surface.environment.users
        access = Access(self._users)
        surface.catalog.add_tool(Tool("delete_user", "Delete an account (admin only)", DELETE_USER_SCHEMA,
                                      access.tool(self._delete_user), destructive=True,
                                      visible_to=access.roles(Role.ADMIN)))

    async def _delete_user(self, arguments: Arguments, user: User, context: CallContext) -> JsonObject:
        if user.role is not Role.ADMIN:
            return text_content(f"Error: forbidden - role {user.role.value} may not call this tool", is_error=True)
        username = str(arguments.get("username", ""))
        if not _exists(self._users, username):
            return text_content(f"Error: user {username} not found", is_error=True)
        return text_content(f"user {username} deleted")


def _exists(users: UserDirectory, username: str) -> bool:
    return any(user.name == username for user in users.users())
