package com.mcpscanner.mcp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public final class McpRequestDetector {

    private static final String TOOLS_CALL_METHOD = "tools/call";
    private static final String TOOLS_LIST_METHOD = "tools/list";
    private static final String RESOURCES_LIST_METHOD = "resources/list";
    private static final String PROMPTS_LIST_METHOD = "prompts/list";
    private static final String INITIALIZE_METHOD = "initialize";
    private static final String RESOURCES_READ_METHOD = "resources/read";
    private static final String PROMPTS_GET_METHOD = "prompts/get";
    private static final String JSON_CONTENT_TYPE_PREFIX = "application/json";
    private static final Set<String> MCP_METHOD_PREFIXES = Set.of(
            "tools/", "resources/", "prompts/", "sampling/", "roots/", "completion/",
            "logging/", "notifications/");
    private static final Set<String> MCP_EXACT_METHODS = Set.of(
            "initialize", "ping");

    /**
     * Strict classification used by the passive scanner to decide whether a wire-level
     * HTTP exchange is a discovery-method JSON-RPC response. Anything that isn't one of
     * the four explicit discovery methods returns {@link #OTHER} — including non-MCP
     * traffic, JSON-RPC errors, non-200 responses, and other valid MCP methods such as
     * {@code tools/call} or {@code resources/templates/list}.
     */
    public enum DiscoveryResponseKind {
        TOOLS_LIST,
        RESOURCES_LIST,
        PROMPTS_LIST,
        INITIALIZE,
        OTHER
    }

    /**
     * Runtime-output classification used by the response-body content scanner. Returns the
     * matching kind only for {@code tools/call}, {@code resources/read}, and
     * {@code prompts/get} exchanges whose response is a 200 JSON-RPC envelope. Disjoint from
     * {@link DiscoveryResponseKind} by method set so the discovery and response scanners
     * never double-fire on a single exchange.
     */
    public enum ResponseContentKind {
        TOOL_CALL,
        RESOURCE_READ,
        PROMPT_GET,
        OTHER
    }

    private McpRequestDetector() {}

    public static McpRequestKind classify(HttpRequestResponse requestResponse) {
        String method = jsonRpcMethod(extractRequestBody(requestResponse));
        if (method == null) {
            return McpRequestKind.NOT_MCP;
        }
        return switch (method) {
            case TOOLS_CALL_METHOD -> McpRequestKind.TOOLS_CALL;
            case TOOLS_LIST_METHOD -> McpRequestKind.TOOLS_LIST;
            case RESOURCES_READ_METHOD -> McpRequestKind.RESOURCES_READ;
            case PROMPTS_GET_METHOD -> McpRequestKind.PROMPTS_GET;
            default -> isMcpMethod(method) ? McpRequestKind.OTHER_MCP : McpRequestKind.NOT_MCP;
        };
    }

    private static boolean isMcpMethod(String method) {
        if (MCP_EXACT_METHODS.contains(method)) {
            return true;
        }
        for (String prefix : MCP_METHOD_PREFIXES) {
            if (method.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static String jsonRpcMethod(String body) {
        if (body == null) {
            return null;
        }
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(body);
            if (!root.path("jsonrpc").isTextual()) {
                return null;
            }
            JsonNode method = root.path("method");
            return method.isTextual() ? method.asText() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    public static String extractBaseUrl(HttpRequestResponse requestResponse) {
        var service = requestResponse.request().httpService();
        String scheme = service.secure() ? "https" : "http";
        return scheme + "://" + buildHostHeader(service);
    }

    public static String buildHostHeader(HttpService service) {
        int port = service.port();
        boolean defaultPort = (service.secure() && port == 443) || (!service.secure() && port == 80);
        return defaultPort ? service.host() : service.host() + ":" + port;
    }

    public static String baseUrl(HttpService service) {
        if (service == null) {
            return "";
        }
        String scheme = service.secure() ? "https" : "http";
        return scheme + "://" + buildHostHeader(service);
    }

    /**
     * Loose "200 OK and not a JSON-RPC error envelope" gate.
     *
     * <p>Returns true when the response is HTTP 200, parses as JSON, and lacks a top-level
     * {@code error} field. Does NOT require {@code jsonrpc:"2.0"} or a {@code result} field
     * to be present — so a partial / malformed-but-success-leaning body still qualifies.
     *
     * <p>Use this when the caller just needs to filter out HTTP-layer failures and explicit
     * JSON-RPC errors before doing its own body inspection. For a strict "this is a
     * well-formed MCP success response with a result envelope", use {@link #isMcpResponseSuccess}.
     */
    public static boolean isNonErrorMcpResponse(HttpRequestResponse response) {
        if (response.response() == null) return false;
        if (response.response().statusCode() != 200) return false;
        try {
            return !McpObjectMapper.INSTANCE.readTree(jsonRpcBody(response.response())).has("error");
        } catch (Exception ignored) {
            return false;
        }
    }

    /**
     * Strict MCP success gate: 200 OK + JSON-RPC envelope + non-null {@code result} + no
     * {@code error}.
     *
     * <p>Tighter than {@link #isNonErrorMcpResponse} — used by checks that need to know the
     * server returned a usable result envelope, not just that it didn't return an error.
     */
    public static boolean isMcpResponseSuccess(HttpRequestResponse response) {
        return parseSuccessfulResult(response) != null;
    }

    public static boolean responseShapesMatch(HttpRequestResponse baseline, HttpRequestResponse probe) {
        JsonNode baselineResult = parseSuccessfulResult(baseline);
        JsonNode probeResult = parseSuccessfulResult(probe);
        if (baselineResult == null || probeResult == null) {
            return false;
        }
        return discoveryShapeSignature(baselineResult).equals(discoveryShapeSignature(probeResult));
    }

    private static JsonNode parseSuccessfulResult(HttpRequestResponse response) {
        if (response == null || response.response() == null) return null;
        if (response.response().statusCode() != 200) return null;
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(jsonRpcBody(response.response()));
            if (!root.path("jsonrpc").isTextual()) return null;
            if (root.has("error")) return null;
            JsonNode result = root.path("result");
            if (result.isMissingNode() || result.isNull()) return null;
            return result;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String discoveryShapeSignature(JsonNode result) {
        if (result.path("tools").isArray()) {
            return "tools:" + sortedFieldValues(result.path("tools"), "name");
        }
        if (result.path("resources").isArray()) {
            return "resources:" + sortedFieldValues(result.path("resources"), "uri");
        }
        if (result.path("prompts").isArray()) {
            return "prompts:" + sortedFieldValues(result.path("prompts"), "name");
        }
        if (result.path("protocolVersion").isTextual()) {
            return "init:"
                    + result.path("protocolVersion").asText() + ":"
                    + result.path("serverInfo").path("name").asText("") + ":"
                    + sortedFieldNames(result.path("capabilities"));
        }
        if (isToolCallResult(result)) {
            return "toolcall:"
                    + result.path("isError").asBoolean(false) + ":"
                    + toolCallContentSignature(result.path("content"));
        }
        return "generic:" + sortedFieldNames(result);
    }

    private static boolean isToolCallResult(JsonNode result) {
        return result.path("content").isArray() || result.path("isError").isBoolean();
    }

    private static String toolCallContentSignature(JsonNode content) {
        if (!content.isArray()) {
            return "";
        }
        StringBuilder text = new StringBuilder();
        for (JsonNode block : content) {
            text.append(block.path("type").asText("")).append(':');
            text.append(block.path("text").asText("")).append('\n');
        }
        return Integer.toHexString(text.toString().hashCode());
    }

    private static String sortedFieldValues(JsonNode array, String fieldName) {
        List<String> values = new ArrayList<>();
        for (JsonNode element : array) {
            values.add(element.path(fieldName).asText(""));
        }
        Collections.sort(values);
        return String.join(",", values);
    }

    private static String sortedFieldNames(JsonNode object) {
        if (!object.isObject()) return "";
        List<String> names = new ArrayList<>();
        object.fieldNames().forEachRemaining(names::add);
        Collections.sort(names);
        return String.join(",", names);
    }

    /**
     * Defense-in-depth filter for the passive content scanner. Returns one of the four
     * discovery kinds only when ALL of the following hold:
     *
     * <ul>
     *   <li>Request was POST with {@code Content-Type: application/json}.</li>
     *   <li>Request body is a JSON-RPC 2.0 envelope with {@code jsonrpc:"2.0"},
     *       {@code method}, and {@code id} present.</li>
     *   <li>Request method is exactly one of {@code tools/list}, {@code resources/list},
     *       {@code prompts/list}, or {@code initialize}.</li>
     *   <li>Response is HTTP 200 with a well-formed JSON-RPC result envelope (no
     *       {@code error}).</li>
     *   <li>Result envelope contains the expected top-level field for the method
     *       ({@code tools}/{@code resources}/{@code prompts} arrays for the list methods,
     *       {@code protocolVersion} string for initialize).</li>
     * </ul>
     *
     * Anything else returns {@link DiscoveryResponseKind#OTHER}, including {@code tools/call}
     * results (which are user data flows, not server-leaked metadata) and other valid
     * MCP methods such as {@code resources/templates/list}.
     */
    public static DiscoveryResponseKind classifyDiscoveryResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return DiscoveryResponseKind.OTHER;
        }
        String requestMethod = discoveryRequestMethod(requestResponse);
        if (requestMethod == null) {
            return DiscoveryResponseKind.OTHER;
        }
        JsonNode result = parseSuccessfulResult(requestResponse);
        if (result == null) {
            return DiscoveryResponseKind.OTHER;
        }
        return matchDiscoveryMethodToShape(requestMethod, result);
    }

    private static String discoveryRequestMethod(HttpRequestResponse requestResponse) {
        HttpRequest request = requestResponse.request();
        if (request == null || !"POST".equalsIgnoreCase(request.method())) {
            return null;
        }
        String contentType = request.headerValue("Content-Type");
        if (contentType == null || !contentType.toLowerCase().contains(JSON_CONTENT_TYPE_PREFIX)) {
            return null;
        }
        String body = request.bodyToString();
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(body);
            if (!"2.0".equals(root.path("jsonrpc").asText())) return null;
            if (root.path("id").isMissingNode() || root.path("id").isNull()) return null;
            JsonNode method = root.path("method");
            return method.isTextual() ? method.asText() : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static DiscoveryResponseKind matchDiscoveryMethodToShape(String method, JsonNode result) {
        return switch (method) {
            case TOOLS_LIST_METHOD ->
                    result.path("tools").isArray() ? DiscoveryResponseKind.TOOLS_LIST
                            : DiscoveryResponseKind.OTHER;
            case RESOURCES_LIST_METHOD ->
                    result.path("resources").isArray() ? DiscoveryResponseKind.RESOURCES_LIST
                            : DiscoveryResponseKind.OTHER;
            case PROMPTS_LIST_METHOD ->
                    result.path("prompts").isArray() ? DiscoveryResponseKind.PROMPTS_LIST
                            : DiscoveryResponseKind.OTHER;
            case INITIALIZE_METHOD ->
                    result.path("protocolVersion").isTextual() ? DiscoveryResponseKind.INITIALIZE
                            : DiscoveryResponseKind.OTHER;
            default -> DiscoveryResponseKind.OTHER;
        };
    }

    public static ResponseContentKind classifyResponseContent(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return ResponseContentKind.OTHER;
        }
        String requestMethod = discoveryRequestMethod(requestResponse);
        if (requestMethod == null) {
            return ResponseContentKind.OTHER;
        }
        if (parseSuccessfulResult(requestResponse) == null) {
            return ResponseContentKind.OTHER;
        }
        return switch (requestMethod) {
            case TOOLS_CALL_METHOD -> ResponseContentKind.TOOL_CALL;
            case RESOURCES_READ_METHOD -> ResponseContentKind.RESOURCE_READ;
            case PROMPTS_GET_METHOD -> ResponseContentKind.PROMPT_GET;
            default -> ResponseContentKind.OTHER;
        };
    }

    public static boolean isToolCallSuccess(HttpRequestResponse response) {
        if (response.response() == null) return false;
        if (response.response().statusCode() != 200) return false;
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(jsonRpcBody(response.response()));
            if (root.has("error")) return false;
            JsonNode result = root.path("result");
            if (result.isMissingNode() || result.isNull()) return false;
            return !result.path("isError").asBoolean(false);
        } catch (Exception ignored) {
            return false;
        }
    }

    /**
     * "Server recognised the method" gate. Looser than {@link #isToolCallSuccess}: any
     * {@code result} key — including {@code null}, tool-error envelopes, or opaque objects —
     * means the server dispatched the call. The only error code that signals non-recognition
     * is {@code -32601 Method not found}; all other JSON-RPC errors indicate the method was
     * recognised and handled.
     */
    public static boolean isMethodRecognised(HttpRequestResponse response) {
        if (response.response() == null) return false;
        if (response.response().statusCode() != 200) return false;
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(jsonRpcBody(response.response()));
            if (root.has("result")) return true;
            JsonNode error = root.path("error");
            if (!error.isObject()) return false;
            JsonNode code = error.path("code");
            return code.isIntegralNumber() && code.intValue() != -32601;
        } catch (Exception ignored) {
            return false;
        }
    }

    public static Optional<Integer> extractErrorCode(HttpRequestResponse requestResponse) {
        HttpResponse response = requestResponse.response();
        if (response == null) {
            return Optional.empty();
        }
        return errorCodeFromBody(jsonRpcBody(response));
    }

    public static Optional<Integer> errorCodeFromBody(String body) {
        if (body == null || body.isEmpty()) {
            return Optional.empty();
        }
        try {
            JsonNode error = McpObjectMapper.INSTANCE.readTree(body).path("error");
            if (!error.isObject()) {
                return Optional.empty();
            }
            JsonNode code = error.path("code");
            if (!code.isIntegralNumber()) {
                return Optional.empty();
            }
            return Optional.of(code.intValue());
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    public static String jsonRpcBody(HttpResponse response) {
        String body = response.bodyToString();
        String contentType = response.headerValue("Content-Type");
        if (contentType != null && contentType.toLowerCase().contains("text/event-stream")) {
            String unwrapped = SseResponseParser.extractJsonRpcResponse(body);
            return unwrapped != null ? unwrapped : body;
        }
        return body;
    }

    private static String extractRequestBody(HttpRequestResponse requestResponse) {
        HttpRequest request = requestResponse.request();
        if (!"POST".equalsIgnoreCase(request.method())) {
            return null;
        }
        String body = request.bodyToString();
        if (body == null || body.isEmpty()) {
            return null;
        }
        return body;
    }
}
