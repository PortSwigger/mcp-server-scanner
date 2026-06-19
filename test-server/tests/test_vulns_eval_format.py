from __future__ import annotations

import inspect
import typing

import pytest

from mcp_test_server.vulns.eval_format import PLUGIN, EvalFormat


async def test_simple_expression_is_evaluated() -> None:
    result = await PLUGIN.handle(format="1+1")

    assert result == "2"


async def test_data_binding_is_exposed_to_expression() -> None:
    result = await PLUGIN.handle(format="data['quote']")

    assert "Stay hungry, stay foolish." in result


async def test_eval_executes_arbitrary_builtin_import() -> None:
    result = await PLUGIN.handle(format="__import__('socket').gethostbyname('localhost')")

    assert result.startswith("127.")


async def test_eval_returns_environment_value_to_prove_exec() -> None:
    result = await PLUGIN.handle(format="__import__('os').name")

    assert result in {"posix", "nt", "java"}


async def test_invalid_expression_raises() -> None:
    with pytest.raises(SyntaxError):
        await PLUGIN.handle(format="not a python expression !!!")


def test_handle_signature_is_typed_for_fastmcp_schema() -> None:
    sig = inspect.signature(EvalFormat.handle)
    assert [p.name for p in sig.parameters.values()] == ["self", "format"]
    hints = typing.get_type_hints(EvalFormat.handle)
    assert hints["format"] is str
    assert hints["return"] is str
