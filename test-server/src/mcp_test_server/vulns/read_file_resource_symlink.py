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

# Name of the symlink planted INSIDE the root that points OUTSIDE it.
LINK_NAME = "exported"
# Name of the out-of-root directory the link targets.
_LINK_TARGET_DIRNAME = "mcp-lab-res-symlink-target"


def _root() -> pathlib.Path:
    return pathlib.Path(os.environ.get(RESOURCE_ROOT_ENV, DEFAULT_RESOURCE_ROOT))


def seed_symlink() -> pathlib.Path:
    """Idempotently plant an in-root symlink that escapes to a sibling dir.

    Returns the link path. Guarded so it only ever creates files under the
    configured resource root and its sibling target dir - never elsewhere.
    """
    root = _root()
    root.mkdir(parents=True, exist_ok=True)
    target_dir = root.parent / _LINK_TARGET_DIRNAME
    target_dir.mkdir(parents=True, exist_ok=True)
    link = root / LINK_NAME
    if not link.is_symlink():
        # Remove any stale non-symlink occupant before planting the link.
        if link.exists():
            link.unlink()
        link.symlink_to(target_dir, target_is_directory=True)
    return link


class ReadFileResourceSymlink(ResourcePlugin):
    name = "read_file_symlink"
    description = "Read a file inside the resource root (symlink-aware)."
    # Distinct scheme so the server routes this fixture unambiguously.
    uri_template = "linkfs:///{path}"

    async def handle_read(self, path: str) -> str:
        # CVE-2025-53109 / CVE-2025-67364: TOCTOU-style symlink escape. The
        # containment check validates the LITERAL link path (which IS inside
        # the root), but open() follows the symlink and reads its realpath
        # TARGET, which lives OUTSIDE the root.
        #
        # DOCUMENTED FALSE-NEGATIVE BOUNDARY: a remote scanner over JSON-RPC
        # cannot plant a symlink, so the Java check is NOT expected to detect
        # this and MUST NOT over-claim it. This fixture exists purely to prove
        # the bug is real locally and to assert the check stays quiet on it.
        decoded = unquote(path)
        # Reject absolute paths up front: pathlib's `_root() / "/etc/passwd"` discards the root and
        # would silently read the absolute target, an UNINTENDED escape that would muddy this
        # fixture's contract. This fixture must represent ONLY the symlink CVE, so the lexical
        # ../ check below remains the sole (broken) containment gate the symlink defeats.
        if decoded.startswith("/"):
            raise PermissionError("absolute paths are not permitted")
        link_relative = (_root() / decoded)
        # The naive check: is the (un-resolved) path lexically under the root?
        # The planted symlink satisfies this, yet escapes on open().
        if os.path.pardir in pathlib.PurePosixPath(decoded).parts:
            raise PermissionError("path is outside the resource root")
        with open(link_relative, "rb") as fh:
            return fh.read(_READ_CAP).decode("utf-8", errors="replace")


PLUGIN = ReadFileResourceSymlink()
