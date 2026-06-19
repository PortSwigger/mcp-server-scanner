from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_resource_encoded
from mcp_test_server.vulns.read_file_resource_encoded import PLUGIN

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)


@pytest.fixture
def resource_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv(read_file_resource_encoded.RESOURCE_ROOT_ENV, str(root))
    return root


async def test_in_root_read_succeeds(resource_root: Path) -> None:
    (resource_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle_read(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


async def test_plain_traversal_is_blocked(resource_root: Path) -> None:
    # Literal `../` is rejected by the decode-after-check filter.
    secret = resource_root.parent / "passwd"
    secret.write_text(_PASSWD)

    with pytest.raises(ValueError, match="traversal blocked"):
        await PLUGIN.handle_read(path="../passwd")


async def test_encoded_traversal_bypasses_filter(resource_root: Path) -> None:
    # The percent-encoded twin slips past the filter (it inspects the still-
    # encoded path) then decodes to a real traversal at open() time.
    secret = resource_root.parent / "passwd"
    secret.write_text(_PASSWD)

    leaked = await PLUGIN.handle_read(path="..%2fpasswd")

    assert "root:x:0:0:root:/root:/bin/bash" in leaked
