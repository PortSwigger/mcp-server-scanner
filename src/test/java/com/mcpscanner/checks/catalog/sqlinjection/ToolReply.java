package com.mcpscanner.checks.catalog.sqlinjection;

record ToolReply(String text, boolean isError) {

    static ToolReply ok(String text) {
        return new ToolReply(text, false);
    }

    static ToolReply toolError(String text) {
        return new ToolReply(text, true);
    }
}
