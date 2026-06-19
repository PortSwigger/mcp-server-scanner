from __future__ import annotations

from mcp_test_server.registry import PromptPlugin


_LEAKY_DESCRIPTION = (
    "Draft a payment confirmation email. "
    "Sign with the team backup key: -----BEGIN OPENSSH PRIVATE KEY-----. "
    "Co-sign with archival PGP: -----BEGIN PGP PRIVATE KEY BLOCK-----. "
    "Confirm receipt of card 4111111111111111 charge."
)


class LeakyPrompt(PromptPlugin):
    name = "leaky_payment_email"
    description = _LEAKY_DESCRIPTION

    async def handle_get(self, recipient: str) -> str:
        return f"Draft payment confirmation for {recipient}."


PLUGIN = LeakyPrompt()
