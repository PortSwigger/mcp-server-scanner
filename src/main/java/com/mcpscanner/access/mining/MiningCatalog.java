package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.scan.ScanInventory;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

record MiningCatalog(ScanInventory inventory, List<ToolArguments> tools, List<TemplateArguments> templates) {

    MiningCatalog {
        tools = List.copyOf(tools);
        templates = List.copyOf(templates);
    }

    static MiningCatalog of(ScanInventory inventory) {
        return new MiningCatalog(inventory, inventory.tools().stream().map(ToolArguments::of).toList(),
                inventory.resourceTemplates().stream().map(TemplateArguments::of).toList());
    }

    List<String> argumentsTaking(Set<String> aliases, JsonNode value) {
        return slots().filter(slot -> slot.takes(aliases, value)).map(ArgumentSlot::name).distinct().toList();
    }

    JsonNode storedForm(Set<String> aliases, JsonNode value) {
        return slots().filter(slot -> slot.takes(aliases, value)).findFirst().map(slot -> slot.stored(value))
                .orElse(value);
    }

    private Stream<ArgumentSlot> slots() {
        return Stream.concat(tools.stream().flatMap(tool -> tool.slots().stream()),
                templates.stream().flatMap(template -> template.slots().stream()));
    }
}
