package com.mcpscanner.mcp;

import java.util.List;

public record McpResourceDefinition(String uri, String name, String description, String mimeType,
                                    List<IconDescriptor> icons) {

    public McpResourceDefinition {
        icons = icons == null ? List.of() : List.copyOf(icons);
    }

    public McpResourceDefinition(String uri, String name, String description, String mimeType) {
        this(uri, name, description, mimeType, List.of());
    }
}
