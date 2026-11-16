package com.mcpscanner.automation;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanTarget;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public final class ItemSeeds {

    private volatile Map<String, SeededArguments> seededTools = Map.of();

    public void seedWith(List<SeedCall> seeds) {
        seededTools = seeds.stream().map(SeededArguments::of).flatMap(Optional::stream)
                .collect(Collectors.toUnmodifiableMap(SeededArguments::toolName, seeded -> seeded,
                        (first, later) -> first));
    }

    public ScanTarget pinned(ScanTarget target) {
        return target instanceof ScanTarget.Tool tool ? pinned(tool.tool()) : target;
    }

    private ScanTarget pinned(McpToolDefinition tool) {
        SeededArguments seed = seededTools.get(tool.name());
        return new ScanTarget.Tool(seed == null ? tool : seed.pinnedOn(tool));
    }
}
