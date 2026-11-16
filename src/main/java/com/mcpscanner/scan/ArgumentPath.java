package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.JsonStep;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.List;

public record ArgumentPath(List<JsonStep> steps) {

    private static final List<JsonStep> ARGUMENTS_IN_PARAMS =
            List.of(new JsonStep.Member("params"), new JsonStep.Member("arguments"));

    public ArgumentPath {
        steps = List.copyOf(steps);
    }

    public static ArgumentPath of(String... names) {
        ArgumentPath path = new ArgumentPath(List.of());
        for (String name : names) {
            path = path.child(name);
        }
        return path;
    }

    public ArgumentPath child(String name) {
        return extendedBy(new JsonStep.Member(name));
    }

    public ArgumentPath firstItem() {
        return extendedBy(new JsonStep.Item(0));
    }

    public void setIn(ObjectNode arguments, JsonNode value) {
        JsonNode holder = arguments;
        for (int i = 0; i < steps.size() - 1; i++) {
            holder = containerAt(holder, steps.get(i), steps.get(i + 1));
        }
        steps.get(steps.size() - 1).place(holder, value);
    }

    public List<JsonStep> stepsInRequest() {
        List<JsonStep> inRequest = new ArrayList<>(ARGUMENTS_IN_PARAMS);
        inRequest.addAll(steps);
        return inRequest;
    }

    private ArgumentPath extendedBy(JsonStep step) {
        List<JsonStep> extended = new ArrayList<>(steps);
        extended.add(step);
        return new ArgumentPath(extended);
    }

    private static JsonNode containerAt(JsonNode holder, JsonStep step, JsonStep next) {
        JsonNode existing = step.in(holder);
        boolean nextIsItem = next instanceof JsonStep.Item;
        if (existing != null && (nextIsItem ? existing.isArray() : existing.isObject())) {
            return existing;
        }
        JsonNode created = nextIsItem
                ? McpObjectMapper.INSTANCE.createArrayNode() : McpObjectMapper.INSTANCE.createObjectNode();
        step.place(holder, created);
        return created;
    }
}
