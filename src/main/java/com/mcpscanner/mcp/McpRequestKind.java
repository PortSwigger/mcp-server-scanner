package com.mcpscanner.mcp;

public enum McpRequestKind {
    TOOLS_CALL,
    TOOLS_LIST,
    RESOURCES_READ,
    PROMPTS_GET,
    OTHER_MCP,
    NOT_MCP;

    public boolean isMcp() {
        return this != NOT_MCP;
    }
}
