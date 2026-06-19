from __future__ import annotations

import inspect
import subprocess
import typing
from typing import Any
from unittest.mock import patch

from mcp_test_server.vulns.ping_host import PLUGIN, PingHost


def _completed(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args="ping", returncode=0, stdout=stdout, stderr=stderr
    )


async def test_happy_path_runs_handler_via_injection_marker() -> None:
    result = await PLUGIN.handle(host="127.0.0.1; echo HAPPY_PATH_MARKER")
    assert "HAPPY_PATH_MARKER" in result


async def test_timeout_returns_truncated_message() -> None:
    def _raise(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="ping", timeout=5)

    with patch("mcp_test_server.vulns.ping_host.subprocess.run", side_effect=_raise):
        result = await PLUGIN.handle(host="example.invalid")

    assert "timeout" in result.lower()


async def test_shell_injection_is_triggerable() -> None:
    result = await PLUGIN.handle(host="; echo INJECTED")
    assert "INJECTED" in result


async def test_output_is_capped_at_4096_chars() -> None:
    with patch(
        "mcp_test_server.vulns.ping_host.subprocess.run",
        return_value=_completed(stdout="A" * 10_000),
    ):
        result = await PLUGIN.handle(host="127.0.0.1")
    assert len(result) == 4096


async def test_output_is_capped_when_stderr_dominates() -> None:
    with patch(
        "mcp_test_server.vulns.ping_host.subprocess.run",
        return_value=_completed(stderr="B" * 10_000),
    ):
        result = await PLUGIN.handle(host="127.0.0.1")
    assert len(result) == 4096


def test_handle_signature_is_typed_for_fastmcp_schema() -> None:
    sig = inspect.signature(PingHost.handle)
    assert [p.name for p in sig.parameters.values()] == ["self", "host"]
    hints = typing.get_type_hints(PingHost.handle)
    assert hints["host"] is str
    assert hints["return"] is str
