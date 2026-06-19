package com.mcpscanner.mcp;

import java.util.List;

public record McpPromptDefinition(String name, String description, List<PromptArgument> arguments,
                                  List<IconDescriptor> icons) {

    public McpPromptDefinition {
        arguments = arguments == null ? List.of() : List.copyOf(arguments);
        icons = icons == null ? List.of() : List.copyOf(icons);
    }

    public McpPromptDefinition(String name, String description, List<PromptArgument> arguments) {
        this(name, description, arguments, List.of());
    }
}
