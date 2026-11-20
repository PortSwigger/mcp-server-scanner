from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from mcp_test_server.weakness import WeaknessSet


class Role(StrEnum):
    ADMIN = "admin"
    MEMBER = "member"
    READER = "reader"


@dataclass(frozen=True)
class User:
    name: str
    role: Role
    token: str


ALICE = User("alice", Role.ADMIN, "alice-token")
BOB = User("bob", Role.MEMBER, "bob-token")
CAROL = User("carol", Role.READER, "carol-token")
SERVICE_ACCOUNT = User("service-account", Role.ADMIN, "")


class IdentityWeakness(StrEnum):
    UNKNOWN_TOKEN_SERVICE_ACCOUNT = "unknown_token_service_account"


TokenRecogniser = Callable[[str], bool]


def recognises_nothing(token: str) -> bool:
    return False


class UserDirectory:
    def __init__(
        self,
        users: Sequence[User] = (ALICE, BOB, CAROL),
        weaknesses: WeaknessSet[IdentityWeakness] | None = None,
        recognised_elsewhere: TokenRecogniser = recognises_nothing,
    ) -> None:
        self._users = tuple(users)
        self._by_token = {user.token: user for user in users}
        self._weaknesses = weaknesses or WeaknessSet()
        self._recognised_elsewhere = recognised_elsewhere

    def users(self) -> tuple[User, ...]:
        return self._users

    def user_for_token(self, token: str) -> User | None:
        known = self._by_token.get(token.strip())
        if known is None and self._is_unrecognised(token.strip()) and self._falls_back_to_service_account():
            return SERVICE_ACCOUNT
        return known

    def _is_unrecognised(self, token: str) -> bool:
        return bool(token) and not self._recognised_elsewhere(token)

    def user_for(self, headers: Mapping[str, str]) -> User | None:
        scheme, _, token = (headers.get("authorization") or "").partition(" ")
        return self.user_for_token(token) if scheme.lower() == "bearer" else None

    def _falls_back_to_service_account(self) -> bool:
        return self._weaknesses.active(IdentityWeakness.UNKNOWN_TOKEN_SERVICE_ACCOUNT)

    def name_for(self, headers: Mapping[str, str]) -> str | None:
        user = self.user_for(headers)
        return user.name if user else None
