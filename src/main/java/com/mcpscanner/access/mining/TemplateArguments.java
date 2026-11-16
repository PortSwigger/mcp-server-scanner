package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.node.MissingNode;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.scan.UriTemplateExpansion;

import java.util.List;

record TemplateArguments(String uriTemplate, List<ArgumentSlot> slots) {

    TemplateArguments {
        slots = List.copyOf(slots);
    }

    static TemplateArguments of(McpResourceTemplateDefinition template) {
        return new TemplateArguments(template.uriTemplate(),
                UriTemplateExpansion.expand(template.uriTemplate()).variables().stream()
                        .map(UriTemplateExpansion.Variable::name).distinct()
                        .filter(variable -> !SecretName.matches(variable))
                        .map(variable -> new ArgumentSlot(variable,
                                Aliases.ofArgument(variable, template.uriTemplate()), SlotType.STRING,
                                MissingNode.getInstance()))
                        .toList());
    }
}
