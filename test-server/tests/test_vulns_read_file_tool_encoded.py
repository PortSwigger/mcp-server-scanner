from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from mcp_test_server.vulns import read_file_tool_encoded
from mcp_test_server.vulns.read_file_tool_encoded import PLUGIN


@pytest.fixture
def sandbox_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(read_file_tool_encoded.SANDBOX_ROOT_ENV, str(tmp_path))
    return tmp_path


async def test_in_root_read_succeeds(sandbox_root: Path) -> None:
    (sandbox_root / "notes.txt").write_text("INSIDE-ROOT-OK")

    result = await PLUGIN.handle(path="notes.txt")

    assert "INSIDE-ROOT-OK" in result


async def test_literal_traversal_is_blocked(sandbox_root: Path) -> None:
    # The raw-path filter correctly rejects a literal ../ before decoding.
    with pytest.raises(ValueError):
        await PLUGIN.handle(path="../etc/passwd")


async def test_encoded_twin_bypasses_the_decode_after_check_filter(sandbox_root: Path) -> None:
    # The encoded twin sails past the raw-path filter and decodes to a real
    # traversal at open() time — the decode-after-check bug.
    secret = sandbox_root.parent / f"secret-{uuid.uuid4().hex}.txt"
    secret.write_text("ENCODED-BYPASS-LEAK")
    try:
        leaked = await PLUGIN.handle(path=f"..%2f{secret.name}")

        assert "ENCODED-BYPASS-LEAK" in leaked
    finally:
        secret.unlink(missing_ok=True)
