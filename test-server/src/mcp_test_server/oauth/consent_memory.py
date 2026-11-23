from __future__ import annotations

import threading
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

CLIENT_ID_PREFIX_SEPARATOR = "_"


@dataclass(frozen=True)
class ConsentSubject:
    client_id: str
    client_name: str
    redirect_uri: str
    scopes: frozenset[str]

    @property
    def redirect_host(self) -> str:
        return urlsplit(self.redirect_uri).hostname or ""

    @property
    def client_id_prefix(self) -> str:
        prefix, separator, _ = self.client_id.rpartition(CLIENT_ID_PREFIX_SEPARATOR)
        return prefix if separator else self.client_id


class ConsentMemory(Protocol):
    def remembers(self, user: str, subject: ConsentSubject) -> bool: ...

    def remember(self, user: str, subject: ConsentSubject) -> None: ...


class ConsentAlwaysGiven:
    def remembers(self, user: str, subject: ConsentSubject) -> bool:
        return True

    def remember(self, user: str, subject: ConsentSubject) -> None:
        return None


class KeyedConsentMemory:
    def __init__(self, key: Callable[[ConsentSubject], Hashable], scope_bound: bool = True) -> None:
        self._key = key
        self._scope_bound = scope_bound
        self._approved: dict[tuple[str, Hashable], frozenset[str]] = {}
        self._lock = threading.Lock()

    def remembers(self, user: str, subject: ConsentSubject) -> bool:
        with self._lock:
            approved = self._approved.get((user, self._key(subject)))
        if approved is None:
            return False
        return not self._scope_bound or subject.scopes <= approved

    def remember(self, user: str, subject: ConsentSubject) -> None:
        key = (user, self._key(subject))
        with self._lock:
            self._approved[key] = self._approved.get(key, frozenset()) | subject.scopes
