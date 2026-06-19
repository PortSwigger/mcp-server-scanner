from __future__ import annotations

import os
import pathlib
from urllib.parse import unquote

from mcp_test_server.registry import ResourcePlugin

# 64 KiB cap is a self-DoS guardrail; this fixture is the correct
# implementation, so the cap is the only limit on a legitimately in-root read.
_READ_CAP = 65536

RESOURCE_ROOT_ENV = "MCP_LAB_RESOURCE_ROOT"
DEFAULT_RESOURCE_ROOT = "/tmp/mcp-lab-res"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(RESOURCE_ROOT_ENV, DEFAULT_RESOURCE_ROOT))


class ReadFileResourceSafe(ResourcePlugin):
    name = "read_file_safe"
    description = "Read a file safely confined to the resource root."
    # Distinct scheme so the server routes this fixture unambiguously.
    uri_template = "safezone:///{path}"

    async def handle_read(self, path: str) -> str:
        # CORRECT IMPLEMENTATION (negative control). The caller path is
        # decoded, joined under the root, then fully canonicalised with
        # resolve() and gated with is_relative_to() against the resolved root.
        # This rejects `../`, encoded twins, absolute paths and prefix-sibling
        # escapes alike, because containment is checked on the REAL path. The
        # Java traversal check must NOT fire against this fixture.
        decoded = unquote(path)
        root = _root().resolve()
        resolved = (root / decoded).resolve()
        if not resolved.is_relative_to(root):
            raise PermissionError("path is outside the resource root")
        with open(resolved, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileResourceSafe()
