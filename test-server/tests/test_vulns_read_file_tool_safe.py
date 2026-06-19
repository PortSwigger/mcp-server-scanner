from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_tool_safe
from mcp_test_server.vulns.read_file_tool_safe import PLUGIN


@pytest.fixture
def sandbox_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(read_file_tool_safe.SANDBOX_ROOT_ENV, str(tmp_path))
    return tmp_path.resolve()


async def test_in_root_read_succeeds(sandbox_root: Path) -> None:
    (sandbox_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


async def test_literal_traversal_is_denied(sandbox_root: Path) -> None:
    secret = sandbox_root.parent / f"secret-{uuid.uuid4().hex}.txt"
    secret.write_text("SHOULD-NOT-LEAK")
    try:
        with pytest.raises(PermissionError):
            await PLUGIN.handle(path=f"../{secret.name}")
    finally:
        secret.unlink(missing_ok=True)


async def test_encoded_traversal_is_denied(sandbox_root: Path) -> None:
    secret = sandbox_root.parent / f"secret-{uuid.uuid4().hex}.txt"
    secret.write_text("SHOULD-NOT-LEAK")
    try:
        with pytest.raises(PermissionError):
            await PLUGIN.handle(path=f"..%2f{secret.name}")
    finally:
        secret.unlink(missing_ok=True)


async def test_prefix_sibling_is_denied(sandbox_root: Path) -> None:
    # The correct is_relative_to() boundary rejects the prefix-sibling escape that
    # fools the naive startswith() check — denied, never a not-found.
    sibling = sandbox_root.parent / f"{sandbox_root.name}_mcpscan"
    sibling.mkdir()
    (sibling / "secret").write_text("SHOULD-NOT-LEAK")

    with pytest.raises(PermissionError):
        await PLUGIN.handle(path=f"../{sandbox_root.name}_mcpscan/secret")


async def test_absolute_path_is_denied(sandbox_root: Path) -> None:
    with pytest.raises(PermissionError):
        await PLUGIN.handle(path="/etc/passwd")
