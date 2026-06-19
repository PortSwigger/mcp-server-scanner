from __future__ import annotations

import os
import pathlib
from urllib.parse import unquote

from mcp_test_server.registry import VulnPlugin

# 64 KiB cap is a self-DoS guardrail; this fixture is the correct
# implementation, so the cap is the only limit on a legitimately in-root read.
_READ_CAP = 65536

SANDBOX_ROOT_ENV = "MCP_LAB_SAFE_ROOT"
DEFAULT_ROOT = "/tmp/mcp-lab-safe"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(SANDBOX_ROOT_ENV, DEFAULT_ROOT))


class ReadFileToolSafe(VulnPlugin):
    name = "read_file_safe_tool"
    description = "Read a file safely confined to the configured workspace root."
    annotations = {"readOnlyHint": True}

    async def handle(self, path: str) -> str:
        # CORRECT IMPLEMENTATION (negative control). The caller path is decoded,
        # joined under the root, then fully canonicalised with resolve() and gated
        # with is_relative_to() against the resolved root. This rejects `../`,
        # encoded twins, absolute paths and prefix-sibling escapes alike, because
        # containment is checked on the REAL path. The Java traversal check must NOT
        # fire against this fixture.
        decoded = unquote(path)
        root = _root().resolve()
        resolved = (root / decoded).resolve()
        if not resolved.is_relative_to(root):
            raise PermissionError(
                f"Access denied - path outside allowed directories: {resolved} not in {root}"
            )
        with open(resolved, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileToolSafe()
