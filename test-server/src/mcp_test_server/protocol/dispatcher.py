from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence

from mcp_test_server.protocol.context import CallContext
from mcp_test_server.protocol.families import FamilySwitches
from mcp_test_server.protocol.handlers import MethodHandler, RequestObserver
from mcp_test_server.protocol.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    JsonObject,
    JsonRpcError,
    failure,
    is_notification,
    is_reply,
    params_of,
    readable_id,
    success,
)

_LOGGER = logging.getLogger(__name__)


def _invalid_request(message_id: object) -> JsonObject:
    return failure(message_id, JsonRpcError(INVALID_REQUEST, "Invalid JSON-RPC message"))


class Dispatcher:
    def __init__(
        self,
        handlers: Iterable[MethodHandler],
        families: FamilySwitches,
        observers: Sequence[RequestObserver],
    ) -> None:
        self._handlers = {handler.method: handler for handler in handlers}
        self._families = families
        self._observers = observers

    def supports(self, method: str) -> bool:
        handler = self._handlers.get(method)
        return handler is not None and self._families.enabled(handler.family)

    async def dispatch(self, message: object, context: CallContext) -> JsonObject | None:
        if not isinstance(message, dict):
            return _invalid_request(None)
        if is_reply(message):
            return None
        if message.get("jsonrpc") != "2.0" or "method" not in message:
            return _invalid_request(readable_id(message))
        self._notify_observers(message, context)
        reply = await self._invoke(message, context)
        return None if is_notification(message) else reply

    def _notify_observers(self, message: JsonObject, context: CallContext) -> None:
        for observer in self._observers:
            observer.observe(message, context)

    async def _invoke(self, message: JsonObject, context: CallContext) -> JsonObject:
        message_id = message.get("id")
        try:
            result = await self._handler_for(str(message["method"])).handle(params_of(message), context)
        except JsonRpcError as error:
            return failure(message_id, error)
        except Exception as error:
            _LOGGER.exception("Handler failed")
            return failure(message_id, JsonRpcError(INTERNAL_ERROR, str(error)))
        return success(message_id, result or {})

    def _handler_for(self, method: str) -> MethodHandler:
        if not self.supports(method):
            raise JsonRpcError(METHOD_NOT_FOUND, f"Method not found: {method}")
        return self._handlers[method]
