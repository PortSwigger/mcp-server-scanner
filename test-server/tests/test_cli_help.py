from __future__ import annotations

import pytest

from mcp_test_server import cli
from mcp_test_server.oauth_discovery import DiscoveryMode


def test_help_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "mcp-test-server" in output
    assert "--host" in output
    assert "--port" in output
    assert "--enable" in output
    assert "--disable" in output
    assert "--list-plugins" in output


def test_help_lists_oauth_discovery_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    output = capsys.readouterr().out
    assert "--oauth-discovery" in output


def test_parse_args_defaults() -> None:
    options = cli.parse_args([])

    assert options.host == "0.0.0.0"
    assert options.port == 8000
    assert options.enable == ()
    assert options.disable == ()
    assert options.oauth_discovery == DiscoveryMode.FULL.value
    assert options.transport_security == "disabled"


def test_oauth_discovery_rejects_unknown_value(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.parse_args(["--oauth-discovery", "bogus"])

    assert exc_info.value.code != 0
    err = capsys.readouterr().err
    assert "--oauth-discovery" in err
    assert "choose from" in err


def test_help_lists_transport_security_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    output = capsys.readouterr().out
    assert "--transport-security" in output


def test_transport_security_rejects_unknown_value(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.parse_args(["--transport-security", "bogus"])

    assert exc_info.value.code != 0
    err = capsys.readouterr().err
    assert "--transport-security" in err
    assert "choose from" in err
