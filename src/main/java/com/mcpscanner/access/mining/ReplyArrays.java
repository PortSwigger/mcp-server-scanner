package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.Leaf;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.StreamSupport;

final class ReplyArrays {

    private final List<ReplyField> fields = new ArrayList<>();

    private ReplyArrays() {
    }

    static List<ReplyField> of(JsonNode result) {
        ReplyArrays collected = new ReplyArrays();
        ReplyRoots.of(result).forEach(root -> collected.walk(root.json(), new ArrayList<>(), root.location()));
        return List.copyOf(collected.fields);
    }

    private void walk(JsonNode node, List<Object> path, String location) {
        if (node.isArray() && objectsOnly(node) && !path.isEmpty()) {
            Leaf leaf = new Leaf(path, withoutSecrets(node));
            fields.add(new ReplyField(location + "." + leaf.pathText(), leaf, node));
        }
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> descend(entry.getValue(), path, entry.getKey(), location));
        } else if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) {
                descend(node.get(index), path, index, location);
            }
        }
    }

    private void descend(JsonNode child, List<Object> path, Object step, String location) {
        List<Object> deeper = new ArrayList<>(path);
        deeper.add(step);
        walk(child, deeper, location);
    }

    private static boolean objectsOnly(JsonNode array) {
        return !array.isEmpty() && StreamSupport.stream(array.spliterator(), false).allMatch(JsonNode::isObject);
    }

    private static JsonNode withoutSecrets(JsonNode node) {
        if (node.isObject()) {
            ObjectNode kept = McpObjectMapper.INSTANCE.createObjectNode();
            node.fields().forEachRemaining(entry -> {
                if (!SecretName.matches(entry.getKey()) && !SecretValue.matches(entry.getValue())) {
                    kept.set(entry.getKey(), withoutSecrets(entry.getValue()));
                }
            });
            return kept;
        }
        if (node.isArray()) {
            ArrayNode kept = McpObjectMapper.INSTANCE.createArrayNode();
            node.forEach(element -> {
                if (!SecretValue.matches(element)) {
                    kept.add(withoutSecrets(element));
                }
            });
            return kept;
        }
        return node;
    }
}
