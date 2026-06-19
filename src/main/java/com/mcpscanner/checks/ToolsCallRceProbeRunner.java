package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.ToolArgRcePayloads.RcePayloadTemplate;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.scan.CodeArgumentHeuristic;

import java.util.List;

public final class ToolsCallRceProbeRunner {

    public record FiredProbe(ToolArgument argument,
                             RcePayloadTemplate payload,
                             String collaboratorSubdomain,
                             String interactionId,
                             HttpRequestResponse response) {}

    private final Http http;

    public ToolsCallRceProbeRunner(Http http) {
        this.http = http;
    }

    public List<DiscoveredTool> discoverTools(HttpRequest baseline) {
        return ToolsListDiscovery.discoverTools(http, baseline);
    }

    public List<ToolArgument> findCodeArguments(List<DiscoveredTool> tools) {
        return ToolArgumentFinder.findArguments(tools, CodeArgumentHeuristic::isCodeLike);
    }

    public FiredProbe fire(HttpRequest baseline,
                           ToolArgument argument,
                           RcePayloadTemplate payload,
                           String collaboratorSubdomain,
                           String interactionId) {
        String rendered = payload.render(collaboratorSubdomain);
        HttpRequestResponse response = http.sendRequest(
                baseline.withBody(ToolsCallBodyBuilder.buildToolsCallBody(argument, rendered)));
        return new FiredProbe(argument, payload, collaboratorSubdomain, interactionId, response);
    }
}
