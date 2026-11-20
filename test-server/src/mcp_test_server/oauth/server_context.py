from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from mcp_test_server.oauth.clients import ClientRegistry
from mcp_test_server.oauth.consent import ConsentPage
from mcp_test_server.oauth.consent_memory import ConsentAlwaysGiven, ConsentMemory, KeyedConsentMemory
from mcp_test_server.oauth.grants import GrantStore
from mcp_test_server.oauth.redirect_policy import RedirectPolicy
from mcp_test_server.oauth.refresh_policy import RefreshPolicy
from mcp_test_server.oauth.sign_in import SignedInSessions
from mcp_test_server.oauth.signer import JwtSigner

DEFAULT_SCOPE = "mcp:tools"
SUPPORTED_SCOPES = ("mcp:tools", "mcp:resources", "mcp:prompts", "mcp:admin")
TEST_SUBJECT = "test-user"


class ConsentMode(StrEnum):
    PROMPT = "prompt"
    AUTO = "auto"
    SIGNED_IN_AUTO = "signed-in-auto"
    REMEMBER_BY_NAME = "remember-by-name"
    REMEMBER_BY_REDIRECT_HOST = "remember-by-redirect-host"
    REMEMBER_BY_CLIENT_ID_PREFIX = "remember-by-client-id-prefix"
    REMEMBER_IGNORES_SCOPE = "remember-ignores-scope"
    REMEMBER_BY_CLIENT = "remember-by-client"

    @property
    def needs_sign_in(self) -> bool:
        return self not in (ConsentMode.PROMPT, ConsentMode.AUTO)

    def memory(self) -> ConsentMemory:
        return _CONSENT_MEMORIES.get(self, _remembered_by_client)()


def _remembered_by_client() -> ConsentMemory:
    return KeyedConsentMemory(lambda subject: subject.client_id)


_CONSENT_MEMORIES: dict[ConsentMode, Callable[[], ConsentMemory]] = {
    ConsentMode.SIGNED_IN_AUTO: ConsentAlwaysGiven,
    ConsentMode.REMEMBER_BY_NAME: lambda: KeyedConsentMemory(lambda subject: subject.client_name),
    ConsentMode.REMEMBER_BY_REDIRECT_HOST: lambda: KeyedConsentMemory(lambda subject: subject.redirect_host),
    ConsentMode.REMEMBER_BY_CLIENT_ID_PREFIX: lambda: KeyedConsentMemory(lambda subject: subject.client_id_prefix),
    ConsentMode.REMEMBER_IGNORES_SCOPE: lambda: KeyedConsentMemory(lambda subject: subject.client_id,
                                                                   scope_bound=False),
}


class RegistrationObserver(Protocol):
    def on_register(self, metadata: dict[str, Any]) -> None: ...


@dataclass(frozen=True)
class AuthorizationServerContext:
    base_url: str
    signer: JwtSigner
    clients: ClientRegistry
    grants: GrantStore
    redirect_policy: RedirectPolicy
    refresh_policy: RefreshPolicy
    consent_page: ConsentPage
    consent_mode: ConsentMode
    consent_memory: ConsentMemory
    sessions: SignedInSessions
    registration_observers: Sequence[RegistrationObserver]
