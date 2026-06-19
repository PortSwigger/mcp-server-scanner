package com.mcpscanner.client;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;

import java.util.List;

/**
 * Callback invoked once per successful connect with the freshly discovered MCP inventory.
 *
 * <p>Defined in {@code client/} (with only mcp/ and Montoya parameter types) so that
 * {@link McpClientManager} can drive post-discovery side effects — notably the sensitive-data
 * content scan in {@code checks/content} — without {@code client/} depending UPWARD on
 * {@code checks/}. The scanner registers itself as an observer at the composition root.
 */
@FunctionalInterface
public interface DiscoveryResultObserver {

    void onDiscovery(ServerMetadata serverMetadata,
                     List<McpToolDefinition> tools,
                     List<McpResourceDefinition> resources,
                     List<McpResourceTemplateDefinition> resourceTemplates,
                     List<McpPromptDefinition> prompts,
                     HttpService host);

    DiscoveryResultObserver NO_OP = (serverMetadata, tools, resources, resourceTemplates, prompts, host) -> {
    };
}
