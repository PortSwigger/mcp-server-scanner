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

# In-root canary advertised via the concrete root-leaking URI.
_ROOT_CANARY = "canary.txt"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(RESOURCE_ROOT_ENV, DEFAULT_RESOURCE_ROOT))


class ReadFileResourcePrefixMatch(ResourcePlugin):
    name = "read_file_prefixmatch"
    description = "Read a file inside the resource root (prefix-validated)."
    # Distinct scheme so the server routes this fixture unambiguously (it must NOT
    # collide with the unrooted read_file file:/// reader).
    uri_template = "prefixmatch:///{path}"

    def concrete_uri(self) -> str:
        # Leak the sandbox root by advertising prefixmatch://<root>/canary.txt in
        # resources/list; a remote check reads the root off this URI and computes
        # the prefix-sharing sibling <root>_mcpscan on the SAME scheme so the
        # follow-up probe routes back to this validator.
        return f"prefixmatch://{(_root().resolve() / _ROOT_CANARY).as_posix()}"

    async def handle_concrete(self) -> str:
        return "in-root canary"

    async def handle_read(self, path: str) -> str:
        # CVE-2025-53110 (EscapeRoute): containment is validated with a NAIVE
        # STRING PREFIX MATCH on the resolved path. Because the comparison is
        # `startswith(str(root))` with no trailing-separator anchoring, a
        # SIBLING directory whose name merely SHARES the root prefix
        # (e.g. root `/tmp/mcp-lab-res` -> `/tmp/mcp-lab-res_mcpscan`)
        # satisfies the check; the server then opens it and, for a NON-EXISTENT
        # sibling, fails with a filesystem not-found. A path that does NOT share
        # the prefix is rejected with an access-denied BEFORE the filesystem is
        # touched. The not-found-vs-denied differential for an out-of-root path
        # is the FP-safe boundary-bypass signal (no planted secret needed); the
        # sandbox root itself leaks via the advertised concrete_uri so a remote
        # check can derive the prefix-sibling probe. A genuine `../` to an
        # unrelated directory fails the prefix check, so this fixture specifically
        # demonstrates the sibling-prefix bypass, not arbitrary traversal.
        decoded = unquote(path)
        # Resolve both sides so the comparison is canonical: on macOS /tmp is a
        # symlink to /private/tmp, so an unresolved root would never prefix-match
        # the resolved target and the bug would be masked. The bug is the missing
        # trailing-separator anchor, NOT a resolve mismatch.
        root = _root().resolve()
        target = (root / decoded).resolve()
        if not str(target).startswith(str(root)):
            raise PermissionError("Access denied - path outside the resource root")
        with open(target, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileResourcePrefixMatch()
