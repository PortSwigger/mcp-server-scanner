from __future__ import annotations

from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_tool_prefixmatch
from mcp_test_server.vulns.list_allowed_directories_tool import PLUGIN


@pytest.fixture
def sandbox_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "allow"
    root.mkdir()
    monkeypatch.setenv(read_file_tool_prefixmatch.SANDBOX_ROOT_ENV, str(root))
    return root.resolve()


async def test_lists_the_configured_root(sandbox_root: Path) -> None:
    result = await PLUGIN.handle()

    assert result.startswith("Allowed directories:")
    assert str(sandbox_root) in result
