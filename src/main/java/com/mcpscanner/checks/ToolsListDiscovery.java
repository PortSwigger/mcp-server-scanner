package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.List;

public final class ToolsListDiscovery {

    public record DiscoveredTool(String name, JsonNode inputSchema) {}

    public static final String TOOLS_LIST_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}";

    private ToolsListDiscovery() {}

    public static List<DiscoveredTool> discoverTools(Http http, HttpRequest baseline) {
        HttpRequestResponse response = http.sendRequest(baseline.withBody(TOOLS_LIST_BODY));
        if (!McpRequestDetector.isNonErrorMcpResponse(response)) {
            return List.of();
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return List.of();
        }
        try {
            JsonNode tools = McpObjectMapper.INSTANCE.readTree(body).path("result").path("tools");
            if (!tools.isArray()) {
                return List.of();
            }
            List<DiscoveredTool> discovered = new ArrayList<>(tools.size());
            for (JsonNode tool : tools) {
                JsonNode name = tool.path("name");
                if (!name.isTextual()) {
                    continue;
                }
                discovered.add(new DiscoveredTool(name.asText(), tool.path("inputSchema")));
            }
            return discovered;
        } catch (Exception ignored) {
            return List.of();
        }
    }
}
