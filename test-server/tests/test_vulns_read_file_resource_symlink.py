from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_resource_symlink
from mcp_test_server.vulns.read_file_resource_symlink import LINK_NAME, PLUGIN, seed_symlink

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@pytest.fixture
def resource_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "root"
    monkeypatch.setenv(read_file_resource_symlink.RESOURCE_ROOT_ENV, str(root))
    return root


def test_seed_is_idempotent(resource_root: Path) -> None:
    first = seed_symlink()
    second = seed_symlink()

    assert first == second
    assert first.is_symlink()


async def test_in_root_symlink_escapes_to_out_of_root_target(resource_root: Path) -> None:
    # DOCUMENTED FALSE-NEGATIVE BOUNDARY: this proves the bug exists locally.
    # The link path (root/<LINK_NAME>/passwd) is lexically in-root and has no
    # `../`, so the naive check passes, yet open() follows the symlink to the
    # out-of-root target. A remote scanner cannot plant this symlink, so the
    # Java check is NOT expected to detect it.
    link = seed_symlink()
    target_dir = link.resolve()
    (target_dir / "passwd").write_text(_PASSWD)

    leaked = await PLUGIN.handle_read(path=f"{LINK_NAME}/passwd")

    assert "root:x:0:0:root:/root:/bin/bash" in leaked
    assert not target_dir.is_relative_to(resource_root.resolve())


async def test_literal_traversal_is_blocked(resource_root: Path) -> None:
    seed_symlink()

    with pytest.raises(PermissionError):
        await PLUGIN.handle_read(path="../passwd")
