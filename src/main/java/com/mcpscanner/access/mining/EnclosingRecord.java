package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

final class EnclosingRecord {

    private EnclosingRecord() {
    }

    static JsonNode of(JsonNode root, List<Object> leafPath) {
        int lastElement = lastIndexStep(leafPath);
        JsonNode record = root;
        for (Object step : leafPath.subList(0, lastElement + 1)) {
            record = step instanceof Integer index ? record.path(index) : record.path((String) step);
        }
        return record;
    }

    private static int lastIndexStep(List<Object> path) {
        for (int index = path.size() - 2; index >= 0; index--) {
            if (path.get(index) instanceof Integer) {
                return index;
            }
        }
        return -1;
    }
}
