from __future__ import annotations

from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
RESOURCE_NOT_FOUND = -32002
HEADER_MISMATCH = -32020

JsonObject = dict[str, Any]


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_error(self) -> JsonObject:
        error: JsonObject = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


def success(message_id: Any, result: JsonObject) -> JsonObject:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def failure(message_id: Any, error: JsonRpcError) -> JsonObject:
    return {"jsonrpc": "2.0", "id": message_id, "error": error.to_error()}


def is_notification(message: JsonObject) -> bool:
    return "method" in message and "id" not in message


def is_reply(message: JsonObject) -> bool:
    return message.get("jsonrpc") == "2.0" and "method" not in message and ("result" in message or "error" in message)


def readable_id(message: JsonObject) -> str | int | float | None:
    message_id = message.get("id")
    if isinstance(message_id, bool) or not isinstance(message_id, (str, int, float)):
        return None
    return message_id


def params_of(message: JsonObject) -> JsonObject:
    params = message.get("params")
    return params if isinstance(params, dict) else {}


def required_string(params: JsonObject, name: str) -> str:
    value = params.get(name)
    if not isinstance(value, str):
        raise JsonRpcError(INVALID_PARAMS, f"Missing or non-string parameter: {name}")
    return value
