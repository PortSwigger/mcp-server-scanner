from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_resource_rooted
from mcp_test_server.vulns.read_file_resource_rooted import PLUGIN

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@pytest.fixture
def resource_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(read_file_resource_rooted.RESOURCE_ROOT_ENV, str(tmp_path))
    return tmp_path


async def test_in_root_read_succeeds(resource_root: Path) -> None:
    (resource_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle_read(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


async def test_plain_traversal_escapes_root(resource_root: Path) -> None:
    secret = resource_root.parent / "passwd"
    secret.write_text(_PASSWD)

    leaked = await PLUGIN.handle_read(path="../passwd")

    assert "root:x:0:0:root:/root:/bin/bash" in leaked


async def test_encoded_traversal_escapes_root(resource_root: Path) -> None:
    secret = resource_root.parent / "passwd"
    secret.write_text(_PASSWD)

    leaked = await PLUGIN.handle_read(path="..%2fpasswd")

    assert "root:x:0:0:root:/root:/bin/bash" in leaked


async def test_absolute_path_is_rejected(resource_root: Path) -> None:
    # The developer's one (broken) guard: absolute paths are refused, so the
    # bug is "tried to restrict reads but forgot traversal", not "no effort".
    with pytest.raises(PermissionError):
        await PLUGIN.handle_read(path="/etc/passwd")
