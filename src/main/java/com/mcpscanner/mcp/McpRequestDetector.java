package com.mcpscanner.mcp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

public final class McpRequestDetector {

    private McpRequestDetector() {}

    public static McpRequestKind classify(HttpRequestResponse requestResponse) {
        return JsonRpcRequestClassifier.classify(requestResponse);
    }

    public static boolean isNotification(HttpRequest request) {
        return isNotificationBody(request.bodyToString());
    }

    public static boolean isNotificationBody(String body) {
        return singleRequest(body).filter(root -> !root.has("id")).isPresent();
    }

    public static boolean isInitializeBody(String body) {
        return singleRequest(body).filter(root -> McpMethods.INITIALIZE.equals(root.path("method").asText()))
                .isPresent();
    }

    public static boolean isToolCallBody(String body) {
        return singleRequest(body).filter(root -> root.has("id")
                && McpMethods.TOOLS_CALL.equals(root.path("method").asText())).isPresent();
    }

    private static Optional<JsonNode> singleRequest(String body) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(body);
            return root != null && root.isObject() && root.path("method").isTextual()
                    ? Optional.of(root) : Optional.empty();
        } catch (Exception unparsable) {
            return Optional.empty();
        }
    }

    public static String extractBaseUrl(HttpRequestResponse requestResponse) {
        return baseUrl(requestResponse.request().httpService());
    }

    public static String jsonRpcBody(String contentType, String body) {
        if (!SseResponseParser.isEventStream(contentType)) {
            return body;
        }
        String unwrapped = SseResponseParser.extractJsonRpcResponse(body);
        return unwrapped != null ? unwrapped : body;
    }

    private static String baseUrl(HttpService service) {
        if (service == null) {
            return "";
        }
        return HttpOrigin.of(service).baseUrl();
    }
}
