from __future__ import annotations

import os
import pathlib
from urllib.parse import unquote

from mcp_test_server.registry import VulnPlugin

# 64 KiB cap is a self-DoS guardrail; it does not constrain the path the
# attacker controls, so the boundary-bypass vulnerability is fully reachable.
_READ_CAP = 65536

SANDBOX_ROOT_ENV = "MCP_LAB_PREFIXMATCH_ROOT"
DEFAULT_ROOT = "/tmp/mcp-lab-prefixmatch"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(SANDBOX_ROOT_ENV, DEFAULT_ROOT)).resolve()


class ReadFileToolPrefixMatch(VulnPlugin):
    name = "read_file_prefixmatch_tool"
    description = "Read a file inside the configured workspace root (prefix-validated)."
    annotations = {"readOnlyHint": True}

    async def handle(self, path: str) -> str:
        # CVE-2025-53110 (EscapeRoute): containment is validated with a NAIVE
        # STRING PREFIX MATCH on the resolved path. Because the comparison is
        # `startswith(str(root))` with no trailing-separator anchoring, a SIBLING
        # path whose name merely SHARES the root prefix (root `/x/allow` ->
        # `/x/allow_mcpscan_ab`) satisfies the check; the server then opens it and
        # fails with a filesystem not-found for a non-existent sibling. A path that
        # does NOT share the prefix is rejected with an access-denied that LEAKS the
        # root, letting a remote check derive the boundary. The not-found-vs-denied
        # differential for an out-of-root path is the FP-safe boundary-bypass signal.
        decoded = unquote(path)
        root = _root()
        target = (root / decoded).resolve() if not os.path.isabs(decoded) else pathlib.Path(decoded)
        if not str(target).startswith(str(root)):
            # Access-denied path also names the root, mirroring server-filesystem's
            # "... not in <root>" rejection that a remote deriver parses.
            raise PermissionError(
                f"Access denied - path outside allowed directories: {target} not in {root}"
            )
        with open(target, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileToolPrefixMatch()
