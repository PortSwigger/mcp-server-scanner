from __future__ import annotations

import os
import pathlib
from urllib.parse import unquote

from mcp_test_server.registry import ResourcePlugin

# 64 KiB cap is a self-DoS guardrail; it does not constrain the path the
# attacker controls, so the traversal vulnerability is fully reachable.
_READ_CAP = 65536

RESOURCE_ROOT_ENV = "MCP_LAB_RESOURCE_ROOT"
DEFAULT_RESOURCE_ROOT = "/tmp/mcp-lab-res"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(RESOURCE_ROOT_ENV, DEFAULT_RESOURCE_ROOT))


class ReadFileResourceRooted(ResourcePlugin):
    name = "read_file_rooted"
    description = "Read a file from inside the configured resource root."
    # Distinct scheme so the server routes this without colliding with the
    # existing unrooted `file:///{path}` reader (read_file.py).
    uri_template = "rooted:///{path}"

    async def handle_read(self, path: str) -> str:
        # BUG CLASS: broken root-join path traversal. The developer ATTEMPTED to
        # restrict reads to the root by rejecting absolute paths, but forgot that
        # a `../` segment also escapes — the classic "tried to restrict, missed
        # traversal" mistake. The percent-decoded path is joined under the claimed
        # root and opened directly: there is NO realpath()/Path.is_relative_to()
        # canonicalisation gate, so a plain `../` segment walks out of the root.
        decoded = unquote(path)
        if decoded.startswith("/"):
            raise PermissionError("absolute paths are not permitted")
        target = _root() / decoded
        with open(target, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileResourceRooted()
