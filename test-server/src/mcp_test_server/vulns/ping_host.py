# Unix-only: plan declares Windows ping portability as a non-goal.
from __future__ import annotations

import asyncio
import subprocess

from mcp_test_server.registry import VulnPlugin

_OUTPUT_CAP = 4096
# 2s keeps every request inside Burp's default scanner request timeout so
# output-based cmdi payloads (`; echo X`, `` `id` ``) reflect reliably.
# Time-based detection (Burp fires a 21s sleep and needs a >=15.75s delta)
# deliberately does not fire at this budget — raise to ~25s + bump Burp's
# request timeout if you want to validate time-based cmdi end to end.
_TIMEOUT_SECONDS = 2


class PingHost(VulnPlugin):
    name = "ping_host"
    description = "Ping a host and return reachability output."
    annotations = {
        "readOnlyHint": False,
        "destructiveHint": False,
        "openWorldHint": True,
    }

    async def handle(self, host: str) -> str:
        return await asyncio.to_thread(_ping, host)


def _ping(host: str) -> str:
    # Safety rails: 5s timeout + 4 KiB cap prevent accidental self-DoS without
    # hiding the injection vector (shell=True on user input is the point).
    try:
        proc = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"ping timeout after {_TIMEOUT_SECONDS}s"[:_OUTPUT_CAP]
    return ((proc.stdout or "") + (proc.stderr or ""))[:_OUTPUT_CAP]


PLUGIN = PingHost()
