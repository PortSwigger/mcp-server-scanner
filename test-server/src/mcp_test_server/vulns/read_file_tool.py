from __future__ import annotations

import os
import pathlib
from urllib.parse import unquote

from mcp_test_server.registry import VulnPlugin

# 64 KiB cap is a self-DoS guardrail; it does not constrain the path the
# attacker controls, so the traversal vulnerability is fully reachable.
_READ_CAP = 65536


class ReadFileTool(VulnPlugin):
    name = "read_file_tool"
    description = "Read a file inside the configured workspace root."
    annotations = {"readOnlyHint": True}

    SANDBOX_ROOT_ENV = "MCP_LAB_WORKSPACE_ROOT"
    DEFAULT_ROOT = "/tmp/mcp-lab"

    @classmethod
    def _root(cls) -> pathlib.Path:
        return pathlib.Path(os.environ.get(cls.SANDBOX_ROOT_ENV, cls.DEFAULT_ROOT))

    async def handle(self, path: str) -> str:
        # BUG: decodes the caller-supplied path, joins it under the claimed
        # workspace root, and opens it directly. No realpath().is_relative_to()
        # gate, so `../` or URL-encoded `..%2f` segments escape the sandbox.
        # Models a common MCP filesystem path-traversal pattern: a configured
        # root with broken path normalisation.
        decoded = unquote(path)
        target = self._root() / decoded
        with open(target, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileTool()
