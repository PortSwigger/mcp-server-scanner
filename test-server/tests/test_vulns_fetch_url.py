from __future__ import annotations

import httpx
import pytest

from mcp_test_server.registry import discover
from mcp_test_server.vulns.fetch_url import PLUGIN


def test_fetch_url_is_registered() -> None:
    names = {plugin.name for plugin in discover()}
    assert "fetch_url" in names


async def test_fetch_url_returns_body_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def _respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="FETCH_URL_BODY_MARKER")

    transport = httpx.MockTransport(_respond)
    original_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _patched_init)

    result = await PLUGIN.handle(url="http://example.test/")

    assert result == "FETCH_URL_BODY_MARKER"


async def test_fetch_url_degrades_gracefully_on_invalid_url() -> None:
    result = await PLUGIN.handle(url="not a url")

    assert result.startswith("fetch failed:")
