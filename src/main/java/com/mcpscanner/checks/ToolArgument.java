package com.mcpscanner.checks;

import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;

public record ToolArgument(DiscoveredTool tool, String name) {}
