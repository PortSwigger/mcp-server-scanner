from __future__ import annotations

import httpx

from mcp_test_server.registry import VulnPlugin

_RESPONSE_CHAR_CAP = 10_240
_REQUEST_TIMEOUT_SECONDS = 5.0


class FetchUrl(VulnPlugin):
    name = "fetch_url"
    description = (
        "Fetch the given URL and return the response body as plain text. "
        "Intentionally vulnerable: no host allowlist, no scheme restriction."
    )

    async def handle(self, url: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
                response = await client.get(url)
        except Exception as exc:  # noqa: BLE001 — degrade gracefully for scanner probes
            return f"fetch failed: {exc}"
        return response.text[:_RESPONSE_CHAR_CAP]


PLUGIN = FetchUrl()
