package com.mcpscanner.mcp;

import java.util.List;
import java.util.Map;

public record ServerMetadata(Map<String, String> serverInfo,
                             String instructions,
                             Map<String, Object> capabilities,
                             List<IconDescriptor> icons) {

    public ServerMetadata {
        icons = icons == null ? List.of() : List.copyOf(icons);
    }

    public ServerMetadata(Map<String, String> serverInfo, String instructions, Map<String, Object> capabilities) {
        this(serverInfo, instructions, capabilities, List.of());
    }

    public static ServerMetadata empty() {
        return new ServerMetadata(Map.of(), "", Map.of(), List.of());
    }
}
