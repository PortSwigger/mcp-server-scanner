from __future__ import annotations

from mcp_test_server.vulns.user_info import PLUGIN


async def test_returns_email_for_passive_checks() -> None:
    result = await PLUGIN.handle()
    assert "alice@example.internal" in result


async def test_returns_credit_card_shaped_value() -> None:
    result = await PLUGIN.handle()
    assert "4111 1111 1111 1111" in result


async def test_returns_private_ip_for_passive_checks() -> None:
    result = await PLUGIN.handle()
    assert "10.0.13.37" in result
