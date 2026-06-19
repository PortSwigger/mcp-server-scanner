from __future__ import annotations

import inspect
import typing
import uuid
from pathlib import Path

import pytest

from mcp_test_server.vulns.read_file_tool import PLUGIN, ReadFileTool


@pytest.fixture
def sandbox_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(ReadFileTool.SANDBOX_ROOT_ENV, str(tmp_path))
    return tmp_path


async def test_read_file_tool_respects_sandbox_for_inbound_paths(sandbox_root: Path) -> None:
    benign = sandbox_root / "notes.txt"
    benign.write_text("INSIDE-SANDBOX-OK")

    result = await PLUGIN.handle(path="notes.txt")

    assert "INSIDE-SANDBOX-OK" in result


async def test_read_file_tool_traversal_escapes_broken_normalisation(sandbox_root: Path) -> None:
    secret = sandbox_root.parent / f"secret-{uuid.uuid4().hex}.txt"
    secret.write_text("STOLEN-SECRET-XYZ")
    try:
        traversal = f"../{secret.name}"

        leaked = await PLUGIN.handle(path=traversal)

        assert "STOLEN-SECRET-XYZ" in leaked
    finally:
        secret.unlink(missing_ok=True)


async def test_read_file_tool_traversal_via_percent_encoded_slash_escapes(sandbox_root: Path) -> None:
    # The payload `..%2f<file>` is single-encoded — one `unquote()` decodes
    # `%2f` to `/` and traversal succeeds. This test locks the
    # single-percent-encoded escape path the broken normalisation enables.
    secret = sandbox_root.parent / f"secret-{uuid.uuid4().hex}.txt"
    secret.write_text("PCT-ENCODED-LEAK")
    try:
        encoded = f"..%2f{secret.name}"

        leaked = await PLUGIN.handle(path=encoded)

        assert "PCT-ENCODED-LEAK" in leaked
    finally:
        secret.unlink(missing_ok=True)


async def test_read_file_tool_double_encoded_does_not_escape_single_unquote(
    sandbox_root: Path,
) -> None:
    # True double-encoding (`..%252f`) does NOT escape
    # because the lab only calls `unquote()` once — `%25` decodes to `%`,
    # leaving `..%2f<file>` literal after a single pass, which `pathlib.Path`
    # treats as a single segment with no traversal. This test locks the lab's
    # exact failure mode: it demonstrates partial-decode mistakes match
    # real-world traversal sinks that decode-once.
    secret = sandbox_root.parent / f"secret-{uuid.uuid4().hex}.txt"
    secret.write_text("DOUBLE-ENCODED-NOT-LEAKED")
    try:
        encoded = f"..%252f{secret.name}"

        with pytest.raises(FileNotFoundError):
            await PLUGIN.handle(path=encoded)
    finally:
        secret.unlink(missing_ok=True)


async def test_missing_file_raises(sandbox_root: Path) -> None:
    with pytest.raises(FileNotFoundError):
        await PLUGIN.handle(path="this-file-does-not-exist-xyzzy")


def test_handle_signature_is_typed_for_fastmcp_schema() -> None:
    sig = inspect.signature(ReadFileTool.handle)
    assert [p.name for p in sig.parameters.values()] == ["self", "path"]
    hints = typing.get_type_hints(ReadFileTool.handle)
    assert hints["path"] is str
    assert hints["return"] is str
