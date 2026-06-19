from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_resource_safe
from mcp_test_server.vulns.read_file_resource_safe import PLUGIN

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@pytest.fixture
def resource_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "mcp-lab-res"
    root.mkdir()
    monkeypatch.setenv(read_file_resource_safe.RESOURCE_ROOT_ENV, str(root))
    return root


async def test_in_root_read_succeeds(resource_root: Path) -> None:
    (resource_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle_read(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


def _seed_outside_passwd(resource_root: Path) -> None:
    (resource_root.parent / "passwd").write_text(_PASSWD)
    sibling = resource_root.parent / f"{resource_root.name}_sensitive"
    sibling.mkdir(exist_ok=True)
    (sibling / "passwd").write_text(_PASSWD)


@pytest.mark.parametrize(
    "path",
    [
        "../passwd",
        "..%2fpasswd",
        "%2e%2e%2fpasswd",
        "..%2f..%2fpasswd",
        "/etc/passwd",
        "../mcp-lab-res_sensitive/passwd",
    ],
)
async def test_every_escape_is_rejected(resource_root: Path, path: str) -> None:
    _seed_outside_passwd(resource_root)

    with pytest.raises(PermissionError):
        await PLUGIN.handle_read(path=path)
