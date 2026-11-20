from __future__ import annotations

import secrets
import string
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

PUBLIC_AUTH_METHOD = "none"
SOFTWARE_ID_TAIL_LENGTH = 16
_ALPHANUMERIC = string.ascii_letters + string.digits


class ClientIdIssuer(Protocol):
    def issue(self, metadata: Mapping[str, Any]) -> str: ...


class RandomClientIds:
    def issue(self, metadata: Mapping[str, Any]) -> str:
        return f"dcr-{secrets.token_hex(8)}"


class SoftwareIdPrefixedClientIds:
    def issue(self, metadata: Mapping[str, Any]) -> str:
        software_id = metadata.get("software_id")
        if not isinstance(software_id, str) or not software_id:
            return secrets.token_hex(16)
        tail = "".join(secrets.choice(_ALPHANUMERIC) for _ in range(SOFTWARE_ID_TAIL_LENGTH))
        return f"{software_id}_{tail}"


@dataclass(frozen=True)
class RegisteredClient:
    client_id: str
    client_name: str
    redirect_uris: tuple[str, ...]
    auth_method: str = PUBLIC_AUTH_METHOD
    secret: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confidential(self) -> bool:
        return self.secret is not None

    def describe(self) -> dict[str, Any]:
        described = {
            **self.metadata,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "redirect_uris": list(self.redirect_uris),
            "token_endpoint_auth_method": self.auth_method,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
        if self.secret is not None:
            described["client_secret"] = self.secret
        return described


PRECONFIGURED_CLIENTS = (
    RegisteredClient(
        client_id="public-client",
        client_name="Preconfigured public client",
        redirect_uris=("https://client.example/callback", "http://127.0.0.1/callback"),
    ),
    RegisteredClient(
        client_id="confidential-client",
        client_name="Preconfigured confidential client",
        redirect_uris=("https://client.example/callback", "http://127.0.0.1/callback"),
        auth_method="client_secret_basic",
        secret="confidential-secret",
    ),
)


class ClientRegistry:
    def __init__(self, client_ids: ClientIdIssuer | None = None) -> None:
        self._client_ids = client_ids or RandomClientIds()
        self._clients = {client.client_id: client for client in PRECONFIGURED_CLIENTS}
        self._lock = threading.Lock()

    def get(self, client_id: str) -> RegisteredClient | None:
        with self._lock:
            return self._clients.get(client_id)

    def register(self, metadata: dict[str, Any], redirect_uris: list[str]) -> RegisteredClient:
        auth_method = str(metadata.get("token_endpoint_auth_method") or PUBLIC_AUTH_METHOD)
        client = RegisteredClient(
            client_id=self._client_ids.issue(metadata),
            client_name=str(metadata.get("client_name") or "Unnamed client"),
            redirect_uris=tuple(redirect_uris),
            auth_method=auth_method,
            secret=None if auth_method == PUBLIC_AUTH_METHOD else secrets.token_urlsafe(24),
            metadata={k: v for k, v in metadata.items() if k not in {"client_id", "client_secret"}},
        )
        with self._lock:
            self._clients[client.client_id] = client
        return client
