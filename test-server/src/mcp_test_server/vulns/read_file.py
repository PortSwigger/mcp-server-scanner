from __future__ import annotations

from urllib.parse import unquote, urlparse

from mcp_test_server.registry import ResourcePlugin

# 64 KiB cap is a self-DoS guardrail; it does not constrain the path the
# attacker controls, so the traversal vulnerability is fully reachable.
_READ_CAP = 65536


class ReadFile(ResourcePlugin):
    name = "read_file"
    description = "Read a file by URI (vulnerable: no sandbox)."
    uri_template = "file:///{path}"

    async def handle_read(self, path: str) -> str:
        target = urlparse(f"file:///{unquote(path)}").path
        with open(target, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFile()
