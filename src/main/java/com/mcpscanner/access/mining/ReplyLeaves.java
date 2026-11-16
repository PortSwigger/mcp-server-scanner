package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.JsonLeaves;

import java.util.List;

final class ReplyLeaves {

    private ReplyLeaves() {
    }

    static List<ReplyField> of(JsonNode result) {
        return ReplyRoots.of(result).stream().flatMap(root -> JsonLeaves.under(root.json(), List.of()).stream()
                .filter(leaf -> !leaf.name().isEmpty())
                .map(leaf -> new ReplyField(root.location() + "." + leaf.pathText(), leaf,
                        EnclosingRecord.of(root.json(), leaf.path())))).toList();
    }
}
