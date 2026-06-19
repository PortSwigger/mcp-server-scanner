from __future__ import annotations

from mcp_test_server.registry import discover


def test_discover_finds_production_plugins() -> None:
    names = {plugin.name for plugin in discover()}
    assert names == {
        "query_user",
        "ping_host",
        "user_info",
        "fetch_url",
        "poisoned_icons_demo",
        "leaky_describe",
        "read_file_tool",
        "read_file_prefixmatch_tool",
        "read_file_encoded_tool",
        "read_file_safe_tool",
        "list_allowed_directories",
        "format_quote",
        "deploy_status",
    }
