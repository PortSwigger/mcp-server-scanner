package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.JsonLeaves;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class ReplyEchoes {

    private static final String ARGUMENTS = "arguments";

    private final Set<JsonNode> placeholders;
    private final ErrorReports errors;

    ReplyEchoes(MiningCall call, JsonNode result) {
        this.placeholders = JsonLeaves.under(placeholderArguments(call), List.of()).stream()
                .map(leaf -> leaf.value())
                .collect(Collectors.toSet());
        this.errors = ErrorReports.in(result);
    }

    boolean isNoise(ReplyField field) {
        return errors.covers(field.leaf().path()) || placeholders.contains(field.leaf().value());
    }

    private static JsonNode placeholderArguments(MiningCall call) {
        JsonNode arguments = call.params().path(ARGUMENTS);
        if (call instanceof MiningCall.ToolCall tool && arguments instanceof ObjectNode sent) {
            ObjectNode placeholders = sent.deepCopy();
            tool.arguments().keySet().forEach(placeholders::remove);
            return placeholders;
        }
        return arguments;
    }
}
