package com.mcpscanner.scan.request;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.UriTemplateExpansion;

import java.util.Map;
import java.util.Optional;

public record McpMessage(RequestFamily family, String method, Optional<ObjectNode> params,
                         Optional<String> routingName, boolean notification,
                         Optional<UriTemplateExpansion.Result> templateExpansion,
                         Optional<ArgumentPath> addedArgument) implements ScanMessage {

    public static McpMessage request(RequestFamily family, String method, ObjectNode params) {
        return new McpMessage(family, method, Optional.of(params), Optional.empty(), false, Optional.empty(), Optional.empty());
    }

    public static McpMessage namedRequest(RequestFamily family, String method, ObjectNode params, String name) {
        return new McpMessage(family, method, Optional.of(params), Optional.ofNullable(name), false, Optional.empty(), Optional.empty());
    }

    public static McpMessage call(RequestFamily family, String method, ObjectNode params) {
        return namedRequest(family, method, params, routingName(params));
    }

    public static McpMessage parameterlessRequest(RequestFamily family, String method) {
        return new McpMessage(family, method, Optional.empty(), Optional.empty(), false, Optional.empty(), Optional.empty());
    }

    public static McpMessage notification(RequestFamily family, String method, ObjectNode params) {
        return new McpMessage(family, method, Optional.of(params), Optional.empty(), true, Optional.empty(), Optional.empty());
    }

    public McpMessage withTemplateExpansion(UriTemplateExpansion.Result expansion) {
        return new McpMessage(family, method, params, routingName, notification, Optional.of(expansion), addedArgument);
    }

    public McpMessage withAddedArgument(ArgumentPath added) {
        return new McpMessage(family, method, params, routingName, notification, templateExpansion,
                Optional.of(added));
    }

    @Override
    public String subject() {
        return routingName.map(name -> method + " " + name).orElse(method);
    }

    @Override
    public HttpRequest renderWith(ScanMessageRenderer renderer, String mcpEndpoint,
                                  Map<String, String> sessionHeaders) {
        return renderer.renderJsonRpc(mcpEndpoint, this, sessionHeaders);
    }

    private static String routingName(ObjectNode params) {
        JsonNode name = params.has("name") ? params.get("name") : params.get("uri");
        return name != null && name.isTextual() ? name.asText() : null;
    }
}
