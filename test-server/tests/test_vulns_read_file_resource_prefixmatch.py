from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_resource_prefixmatch
from mcp_test_server.vulns.read_file_resource_prefixmatch import PLUGIN

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@pytest.fixture
def resource_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "mcp-lab-res"
    root.mkdir()
    monkeypatch.setenv(read_file_resource_prefixmatch.RESOURCE_ROOT_ENV, str(root))
    return root


async def test_in_root_read_succeeds(resource_root: Path) -> None:
    (resource_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle_read(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


async def test_sibling_sharing_prefix_is_readable_the_bug(resource_root: Path) -> None:
    # CVE-2025-53110: a sibling directory whose name shares the root's prefix
    # passes the naive startswith() check and is readable. The sibling name is
    # the exact one the scanner's prefix-sibling probe emits (<root>_mcpscan),
    # so this fixture genuinely represents the probe path.
    sibling = resource_root.parent / f"{resource_root.name}_mcpscan"
    sibling.mkdir()
    (sibling / "passwd").write_text(_PASSWD)

    leaked = await PLUGIN.handle_read(path=f"../{resource_root.name}_mcpscan/passwd")

    assert "root:x:0:0:root:/root:/bin/bash" in leaked


async def test_nonexistent_prefix_sibling_returns_not_found_not_denied(resource_root: Path) -> None:
    # The error-differential oracle keys on a NON-EXISTENT prefix-sharing sibling: the naive
    # startswith() check passes (the prefix matches) so the handler reaches open() and raises a
    # filesystem not-found, NOT an access-denied. No planted secret is required.
    with pytest.raises(FileNotFoundError):
        await PLUGIN.handle_read(path=f"../{resource_root.name}_mcpscan_zz/missing")


async def test_true_traversal_to_unrelated_dir_is_blocked(resource_root: Path) -> None:
    # A genuine `../` into a directory NOT sharing the prefix fails the prefix check with an
    # access-denied (the deny-control the oracle needs), BEFORE the filesystem is touched - proving
    # the bug is specifically the sibling-prefix case.
    unrelated = resource_root.parent / "etc"
    unrelated.mkdir()
    (unrelated / "passwd").write_text(_PASSWD)

    with pytest.raises(PermissionError, match="Access denied"):
        await PLUGIN.handle_read(path="../etc/passwd")


def test_concrete_uri_leaks_resolved_root(resource_root: Path) -> None:
    # The concrete root-leaking URI lets a remote check read off the real
    # sandbox root and derive the prefix-sibling probe.
    concrete = PLUGIN.concrete_uri()

    assert concrete.startswith("prefixmatch://")
    assert str(resource_root.resolve()) in concrete
    assert concrete.endswith("/canary.txt")
