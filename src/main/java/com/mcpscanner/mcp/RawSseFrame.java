package com.mcpscanner.mcp;

public record RawSseFrame(String text, byte[] bytes) {
}
