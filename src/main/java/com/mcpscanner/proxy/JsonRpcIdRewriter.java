package com.mcpscanner.proxy;

import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.IOException;
import java.util.function.LongSupplier;

final class JsonRpcIdRewriter {

    private static final String ID_FIELD = "id";
    private static final ObjectMapper MAPPER = McpObjectMapper.INSTANCE;

    private final LongSupplier idAllocator;
    private final Logging logging;
    private final McpEventLog eventLog;

    JsonRpcIdRewriter(LongSupplier idAllocator, Logging logging) {
        this(idAllocator, logging, McpEventLog.noop());
    }

    JsonRpcIdRewriter(LongSupplier idAllocator, Logging logging, McpEventLog eventLog) {
        this.idAllocator = idAllocator;
        this.logging = logging;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    String rewrite(String body) {
        if (body == null || body.isEmpty()) {
            return body;
        }
        try {
            JsonNode root = MAPPER.readTree(body);
            if (root instanceof ObjectNode object) {
                return rewriteObjectId(object) ? MAPPER.writeValueAsString(object) : body;
            }
            if (root instanceof ArrayNode array) {
                return rewriteArrayIds(array) ? MAPPER.writeValueAsString(array) : body;
            }
            return body;
        } catch (IOException e) {
            if (logging != null) {
                logging.logToError("Failed to rewrite JSON-RPC id: " + e.getMessage());
            }
            eventLog.warn("Failed to rewrite JSON-RPC id: " + e.getMessage());
            return body;
        }
    }

    // Force long ids so within-session uniqueness holds regardless of what the
    // client builder chose - stringified longs collide less often in FastMCP's
    // _request_streams[str(id)] routing than mixed string/number ids would.
    private boolean rewriteObjectId(ObjectNode object) {
        if (!object.has(ID_FIELD)) {
            return false;
        }
        object.set(ID_FIELD, LongNode.valueOf(idAllocator.getAsLong()));
        return true;
    }

    private boolean rewriteArrayIds(ArrayNode array) {
        boolean rewroteAny = false;
        for (JsonNode element : array) {
            if (element instanceof ObjectNode object && rewriteObjectId(object)) {
                rewroteAny = true;
            }
        }
        return rewroteAny;
    }
}
