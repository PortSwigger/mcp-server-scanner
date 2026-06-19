from __future__ import annotations

import os
import pathlib

from mcp_test_server.registry import VulnPlugin
from mcp_test_server.vulns import read_file_tool_prefixmatch


class ListAllowedDirectoriesTool(VulnPlugin):
    name = "list_allowed_directories"
    description = "List the directories this server is allowed to read from."
    annotations = {"readOnlyHint": True}

    async def handle(self) -> str:
        # Mirrors @modelcontextprotocol/server-filesystem's list_allowed_directories
        # output shape so a remote check can derive the sandbox root from a read-only
        # discovery call (the first, highest-priority root-derivation strategy).
        root = pathlib.Path(
            os.environ.get(
                read_file_tool_prefixmatch.SANDBOX_ROOT_ENV,
                read_file_tool_prefixmatch.DEFAULT_ROOT,
            )
        ).resolve()
        return f"Allowed directories:\n{root}"


PLUGIN = ListAllowedDirectoriesTool()
