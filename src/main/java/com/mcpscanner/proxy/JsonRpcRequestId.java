package com.mcpscanner.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

final class JsonRpcRequestId {

    private static final String ID_FIELD = "id";

    private JsonRpcRequestId() {}

    static boolean sameApartFromId(byte[] before, byte[] after) {
        if (Arrays.equals(before, after)) {
            return true;
        }
        Optional<ObjectNode> original = objectIn(before);
        Optional<ObjectNode> altered = objectIn(after);
        return original.isPresent() && altered.isPresent()
                && withoutId(original.get()).equals(withoutId(altered.get()));
    }

    private static ObjectNode withoutId(ObjectNode request) {
        ObjectNode copy = request.deepCopy();
        copy.remove(ID_FIELD);
        return copy;
    }

    private static Optional<ObjectNode> objectIn(byte[] body) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(body);
            return root instanceof ObjectNode object ? Optional.of(object) : Optional.empty();
        } catch (IOException notJson) {
            return Optional.empty();
        }
    }
}
