package com.mcpscanner.access.mining;

import com.mcpscanner.mcp.ToolSafety;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.mcp.McpToolDefinition;

import java.util.List;
import java.util.Optional;

public final class MiningPreferences {

    private final ExtensionConfigStore config;

    public MiningPreferences(ExtensionConfigStore config) {
        this.config = config;
    }

    public int passes() {
        return Optional.ofNullable(config.miningPasses()).flatMap(MiningPreferences::parsedPasses)
                .orElse(MiningSettings.DEFAULT_PASSES);
    }

    public void setPasses(int passes) {
        config.setMiningPasses(Integer.toString(MiningSettings.defaults().withPasses(passes).passes()));
    }

    public WriteToolOptIn writeTools() {
        return Optional.ofNullable(config.miningWriteTools()).flatMap(WriteToolOptIn::decode)
                .orElse(WriteToolOptIn.NONE);
    }

    public void setWriteTools(WriteToolOptIn optIn) {
        config.setMiningWriteTools(optIn.encoded());
    }

    public boolean minedIdsInWriteTools() {
        return config.minedIdsInWriteTools();
    }

    public void setMinedIdsInWriteTools(boolean use) {
        config.setMinedIdsInWriteTools(use);
    }

    public MiningSettings settings(List<McpToolDefinition> tools) {
        return MiningSettings.defaults().withPasses(passes()).withAllowedTools(writeTools().allowedTools(tools))
                .withRequestCeiling(Math.toIntExact(config.resourceCap(ResourceCap.MINING_REQUESTS_PER_USER)));
    }

    public static List<McpToolDefinition> writeToolsIn(List<McpToolDefinition> tools) {
        return tools.stream().filter(ToolSafety::needsOptIn).toList();
    }

    private static Optional<Integer> parsedPasses(String stored) {
        try {
            int passes = Integer.parseInt(stored.trim());
            return passes >= MiningSettings.MIN_PASSES && passes <= MiningSettings.MAX_PASSES
                    ? Optional.of(passes) : Optional.empty();
        } catch (NumberFormatException unreadable) {
            return Optional.empty();
        }
    }
}
