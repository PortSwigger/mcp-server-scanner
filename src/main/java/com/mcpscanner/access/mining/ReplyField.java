package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.Leaf;

record ReplyField(String path, Leaf leaf, JsonNode record) {

    String key() {
        return leaf.name();
    }

    String parentKey() {
        return leaf.parentKey();
    }
}
