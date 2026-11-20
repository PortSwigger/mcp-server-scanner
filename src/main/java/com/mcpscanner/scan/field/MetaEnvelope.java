package com.mcpscanner.scan.field;

import com.mcpscanner.mcp.JsonLeaf;
import com.mcpscanner.mcp.JsonLeafLocator;
import com.mcpscanner.mcp.JsonStep;

import java.util.List;

public final class MetaEnvelope {

    private static final List<JsonStep> PATH = List.of(new JsonStep.Member("params"), new JsonStep.Member("_meta"));

    private MetaEnvelope() {}

    public static boolean contains(JsonLeaf leaf) {
        return contains(leaf.steps());
    }

    public static boolean contains(List<JsonStep> steps) {
        return steps.size() >= PATH.size() && steps.subList(0, PATH.size()).equals(PATH);
    }

    public static boolean carriedBy(byte[] body) {
        return JsonLeafLocator.paramsLeaves(body).stream()
                .anyMatch(MetaEnvelope::contains);
    }
}
