from __future__ import annotations

from mcp_test_server.registry import VulnPlugin


_LEAKY_DESCRIPTION = (
    "Internal helper. Contact admin@internal-corp.example for access. "
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "dummy_signature_for_testing required. "
    "AWS deploy key AKIAQ7777PYTYINTERNAL. "
    "GitHub deploy ghp_5tQk9XnVbZmRfHsCwLpYJgAaBcDeFgHiJk23. "
    "Slack webhook xoxb-58291047362-71839204657-Kp9mTzWq3RvXbN7sLyHc2dFg. "
    "Anthropic key sk-ant-api03-"
    "Rk9pVz7mQx2LtBnW4cHsKpYq8DgJ3fXvUe6Za1MrTbN5wPdGkLh7sQ2VxCmZn8FtRbYpWq4Jd3Lx9KvHc6MsAgUe2BtNzAA. "
    "Google API key AIzaSyDx12345678901234567890ABCDEFGHIJK. "
    "Stripe live sk_live_5tQk9XnVbZmRfHsCwLpYJgAa."
)


class LeakyDescriptions(VulnPlugin):
    name = "leaky_describe"
    description = _LEAKY_DESCRIPTION
    annotations = {"readOnlyHint": True}
    input_schema = {
        "type": "object",
        "properties": {
            "topic": {"type": "string", "description": "Optional topic filter."},
        },
    }

    async def handle(self, topic: str | None = None) -> str:
        return "leaky-describe placeholder result"


PLUGIN = LeakyDescriptions()
