from __future__ import annotations

import os
import pathlib
from urllib.parse import unquote

from mcp_test_server.registry import VulnPlugin

# 64 KiB cap is a self-DoS guardrail; it does not constrain the path the
# attacker controls, so the traversal vulnerability is fully reachable.
_READ_CAP = 65536

SANDBOX_ROOT_ENV = "MCP_LAB_ENCODED_ROOT"
DEFAULT_ROOT = "/tmp/mcp-lab-encoded"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(SANDBOX_ROOT_ENV, DEFAULT_ROOT))


class ReadFileToolEncoded(VulnPlugin):
    name = "read_file_encoded_tool"
    description = "Read a file inside the configured workspace root (traversal filtered)."
    annotations = {"readOnlyHint": True}

    async def handle(self, path: str) -> str:
        # BUG CLASS: decode-after-check encoding bypass (EscapeRoute family).
        # The traversal filter inspects the RAW, still-encoded path and rejects a
        # literal `../` or `..\`. Only AFTER the check passes is the path
        # percent-decoded and opened. A literal `../` is correctly blocked, but a
        # percent-encoded twin (`%2e%2e%2f`, `..%2f`) sails past the filter and
        # decodes to a real traversal at open() time. The plain-vs-encoded
        # differential is the high-confidence remote signal: a present-but-broken
        # sanitizer.
        if "../" in path or "..\\" in path:
            raise ValueError("path traversal blocked")
        decoded = unquote(path)
        target = _root() / decoded
        with open(target, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileToolEncoded()
