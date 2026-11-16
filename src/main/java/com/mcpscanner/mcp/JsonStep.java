package com.mcpscanner.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

public sealed interface JsonStep {

    String appendedTo(String path);

    JsonNode in(JsonNode holder);

    void place(JsonNode holder, JsonNode value);

    record Member(String name) implements JsonStep {
        @Override
        public String appendedTo(String path) {
            return path.isEmpty() ? name : path + "." + name;
        }

        @Override
        public JsonNode in(JsonNode holder) {
            return holder.get(name);
        }

        @Override
        public void place(JsonNode holder, JsonNode value) {
            ((ObjectNode) holder).set(name, value);
        }
    }

    record Item(int index) implements JsonStep {
        @Override
        public String appendedTo(String path) {
            return path + "[" + index + "]";
        }

        @Override
        public JsonNode in(JsonNode holder) {
            return holder.get(index);
        }

        @Override
        public void place(JsonNode holder, JsonNode value) {
            ((ArrayNode) holder).add(value);
        }
    }

    static String pathOf(List<JsonStep> steps) {
        String path = "";
        for (JsonStep step : steps) {
            path = step.appendedTo(path);
        }
        return path;
    }
}
