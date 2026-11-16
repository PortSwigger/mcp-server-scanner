package com.mcpscanner.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.IOException;

final class JsonRpcEnvelopes {

    private static final String JSONRPC_VERSION = "2.0";

    private JsonRpcEnvelopes() {
    }

    static boolean isMalformedRequest(String body) {
        JsonNode message = parse(body);
        return !message.isObject()
                || !JSONRPC_VERSION.equals(message.path("jsonrpc").textValue())
                || !message.path("method").isTextual();
    }

    private static JsonNode parse(String json) {
        try {
            JsonNode parsed = McpObjectMapper.INSTANCE.readTree(json);
            return parsed == null ? MissingNode.getInstance() : parsed;
        } catch (IOException unparsable) {
            return MissingNode.getInstance();
        }
    }
}
