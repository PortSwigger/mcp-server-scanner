from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_tool_prefixmatch
from mcp_test_server.vulns.read_file_tool_prefixmatch import PLUGIN

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@pytest.fixture
def sandbox_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "allow"
    root.mkdir()
    monkeypatch.setenv(read_file_tool_prefixmatch.SANDBOX_ROOT_ENV, str(root))
    return root.resolve()


async def test_in_root_read_succeeds(sandbox_root: Path) -> None:
    (sandbox_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


async def test_existing_sibling_sharing_prefix_is_readable_the_bug(sandbox_root: Path) -> None:
    # CVE-2025-53110: a sibling whose name shares the root's prefix passes the
    # naive startswith() check and is readable.
    sibling = sandbox_root.parent / f"{sandbox_root.name}_mcpscan"
    sibling.mkdir()
    (sibling / "passwd").write_text(_PASSWD)

    leaked = await PLUGIN.handle(path=f"../{sandbox_root.name}_mcpscan/passwd")

    assert "root:x:0:0:root:/root:/bin/bash" in leaked


async def test_nonexistent_prefix_sibling_raises_not_found_not_denied(sandbox_root: Path) -> None:
    # The FP-safe boundary-bypass signal: a NON-EXISTENT sibling sharing the prefix
    # passes containment (startswith) then fails at open() with a filesystem
    # not-found — NOT an access-denied. This is exactly what the remote oracle keys
    # on, with no planted secret.
    with pytest.raises(FileNotFoundError):
        await PLUGIN.handle(path=f"../{sandbox_root.name}_mcpscan_zz/does-not-exist")


async def test_out_of_root_path_is_denied_with_root_leaked(sandbox_root: Path) -> None:
    # A path that does NOT share the root prefix is rejected before any filesystem
    # access, and the rejection LEAKS the root so a remote deriver can parse it.
    with pytest.raises(PermissionError) as excinfo:
        await PLUGIN.handle(path="/etc/nonexistent-elsewhere")

    message = str(excinfo.value)
    assert "Access denied" in message
    assert str(sandbox_root) in message
