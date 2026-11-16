package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class ErrorReports {

    private static final Set<String> ERROR_KEYS = Set.of("error", "errors", "failure", "failures");
    private static final Set<String> REPORT_KEYS = Set.of("message", "code", "reason", "detail", "details",
            "status", "type");

    private final Set<List<Object>> reported = new HashSet<>();

    private ErrorReports() {
    }

    static ErrorReports in(JsonNode result) {
        ErrorReports reports = new ErrorReports();
        ReplyRoots.of(result).forEach(root -> reports.walk(root.json(), new ArrayList<>(), false));
        return reports;
    }

    boolean covers(List<Object> leafPath) {
        return reported.stream().anyMatch(prefix -> leafPath.size() >= prefix.size()
                && leafPath.subList(0, prefix.size()).equals(prefix));
    }

    private void walk(JsonNode node, List<Object> path, boolean underErrorKey) {
        if (underErrorKey && node.isObject() && REPORT_KEYS.stream().anyMatch(node::has)) {
            reported.add(List.copyOf(path));
            return;
        }
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> visitEntry(entry.getKey(), entry.getValue(), path, underErrorKey));
        } else if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) {
                walk(node.get(index), extended(path, index), underErrorKey);
            }
        }
    }

    private void visitEntry(String key, JsonNode value, List<Object> path, boolean underErrorKey) {
        List<Object> deeper = extended(path, key);
        if (isErrorKey(key) && value.isValueNode()) {
            reported.add(deeper);
        } else {
            walk(value, deeper, underErrorKey || isErrorKey(key));
        }
    }

    private static boolean isErrorKey(String key) {
        return ERROR_KEYS.contains(Aliases.normalise(key));
    }

    private static List<Object> extended(List<Object> path, Object step) {
        List<Object> deeper = new ArrayList<>(path);
        deeper.add(step);
        return deeper;
    }
}
