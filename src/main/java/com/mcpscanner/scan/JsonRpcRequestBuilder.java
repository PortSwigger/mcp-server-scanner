package com.mcpscanner.scan;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.auth.AuthHeaders;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.ArgumentValueLocator.ValueByteRange;
import com.mcpscanner.scan.ArgumentValueLocator.ValueKind;
import com.mcpscanner.scan.ArgumentsObjectLocator.ArgumentsObjectRange;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

public class JsonRpcRequestBuilder {

    private static final ObjectMapper MAPPER = McpObjectMapper.INSTANCE;
    private static final String ARGUMENTS_FIELD = "arguments";
    private static final String TOOLS_CALL_METHOD = "tools/call";
    private static final String PROMPTS_GET_METHOD = "prompts/get";
    private static final String RESOURCES_READ_METHOD = "resources/read";
    private static final Pattern HEADER_NAME_TOKEN = Pattern.compile("^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$");

    private final LongSupplier idAllocator;

    public JsonRpcRequestBuilder() {
        this(() -> 1L);
    }

    public JsonRpcRequestBuilder(LongSupplier idAllocator) {
        this.idAllocator = idAllocator;
    }

    public record RawRequestWithOffsets(String rawHttpRequest, List<InsertionPointOffset> offsets) {}

    public record RequestWithOffsets(HttpRequest request, List<InsertionPointOffset> offsets) {}

    public RawRequestWithOffsets buildRaw(String endpoint, String toolName, String argumentsJson,
                                          Map<String, String> authHeaders) {
        String jsonBody = buildToolsCallBody(toolName, argumentsJson);
        return assembleRawRequest(endpoint, jsonBody, authHeaders, this::computeArgumentOffsets);
    }

    public RequestWithOffsets build(String endpoint, String toolName, String argumentsJson, AuthStrategy auth) {
        return build(endpoint, toolName, argumentsJson, auth.headers());
    }

    public RequestWithOffsets build(String endpoint, String toolName, String argumentsJson,
                                    Map<String, String> headers) {
        return toHttpRequest(endpoint, buildRaw(endpoint, toolName, argumentsJson, headers));
    }

    public RawRequestWithOffsets buildPromptGetRaw(String endpoint, String promptName, String argumentsJson,
                                                   Map<String, String> authHeaders) {
        String jsonBody = buildPromptGetBody(promptName, argumentsJson);
        return assembleRawRequest(endpoint, jsonBody, authHeaders, this::computeArgumentOffsets);
    }

    public RequestWithOffsets buildPromptGet(String endpoint, String promptName, String argumentsJson,
                                             Map<String, String> headers) {
        return toHttpRequest(endpoint, buildPromptGetRaw(endpoint, promptName, argumentsJson, headers));
    }

    public RawRequestWithOffsets buildResourceReadRaw(String endpoint, String uri,
                                                      Map<String, String> authHeaders) {
        String jsonBody = buildResourceReadBody(uri);
        return assembleRawRequest(endpoint, jsonBody, authHeaders, this::computeUriOffsets);
    }

    public RequestWithOffsets buildResourceRead(String endpoint, String uri, Map<String, String> headers) {
        return toHttpRequest(endpoint, buildResourceReadRaw(endpoint, uri, headers));
    }

    public RawRequestWithOffsets buildResourceTemplateReadRaw(String endpoint, String uriTemplate,
                                                              Map<String, String> authHeaders) {
        UriTemplateExpansion.Result expansion = UriTemplateExpansion.expand(uriTemplate);
        String jsonBody = buildResourceReadBody(expansion.expandedUri());
        return assembleRawRequest(endpoint, jsonBody, authHeaders,
                (bodyBytes, bodyStartOffset) -> computeTemplateVariableOffsets(bodyBytes, bodyStartOffset, expansion));
    }

    public RequestWithOffsets buildResourceTemplateRead(String endpoint, String uriTemplate,
                                                       Map<String, String> headers) {
        return toHttpRequest(endpoint, buildResourceTemplateReadRaw(endpoint, uriTemplate, headers));
    }

    @FunctionalInterface
    private interface OffsetComputer {
        List<InsertionPointOffset> compute(byte[] bodyBytes, int bodyStartOffset);
    }

    private RawRequestWithOffsets assembleRawRequest(String endpoint, String jsonBody,
                                                     Map<String, String> authHeaders,
                                                     OffsetComputer offsetComputer) {
        byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);

        URI uri = URI.create(endpoint);
        String headers = buildHeadersBlock(extractPath(uri), buildHostHeader(uri), bodyBytes.length, authHeaders);
        byte[] headerBytes = headers.getBytes(StandardCharsets.UTF_8);

        int bodyStartOffset = headerBytes.length + 2;
        List<InsertionPointOffset> offsets = offsetComputer.compute(bodyBytes, bodyStartOffset);

        return new RawRequestWithOffsets(headers + "\r\n" + jsonBody, offsets);
    }

    private RequestWithOffsets toHttpRequest(String endpoint, RawRequestWithOffsets raw) {
        HttpRequest request = HttpRequest.httpRequest(HttpService.httpService(endpoint), raw.rawHttpRequest());
        return new RequestWithOffsets(request, raw.offsets());
    }

    private String buildHostHeader(URI uri) {
        int port = uri.getPort();
        boolean isDefaultPort = port == -1
                || ("https".equals(uri.getScheme()) && port == 443)
                || ("http".equals(uri.getScheme()) && port == 80);
        return isDefaultPort ? uri.getHost() : uri.getHost() + ":" + port;
    }

    private String extractPath(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        String query = uri.getRawQuery();
        return query != null ? path + "?" + query : path;
    }

    private String buildToolsCallBody(String toolName, String argumentsJson) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", toolName);
        params.put(ARGUMENTS_FIELD, parseArguments(argumentsJson));
        return serialiseEnvelope(TOOLS_CALL_METHOD, params);
    }

    private String buildPromptGetBody(String promptName, String argumentsJson) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", promptName);
        params.put(ARGUMENTS_FIELD, parseArguments(argumentsJson));
        return serialiseEnvelope(PROMPTS_GET_METHOD, params);
    }

    private String buildResourceReadBody(String uri) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("uri", uri);
        return serialiseEnvelope(RESOURCES_READ_METHOD, params);
    }

    private Map<String, Object> parseArguments(String argumentsJson) {
        try {
            return MAPPER.readValue(argumentsJson, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid arguments JSON", e);
        }
    }

    private String serialiseEnvelope(String method, Map<String, Object> params) {
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("jsonrpc", "2.0");
            body.put("id", idAllocator.getAsLong());
            body.put("method", method);
            body.put("params", params);
            return MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialise JSON-RPC body for " + method, e);
        }
    }

    private String buildHeadersBlock(String path, String host, int contentLength,
                                     Map<String, String> authHeaders) {
        StringBuilder sb = new StringBuilder();
        sb.append("POST ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        sb.append("Content-Type: application/json\r\n");
        sb.append("Accept: application/json, text/event-stream\r\n");
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        for (Map.Entry<String, String> header : authHeaders.entrySet()) {
            String name = header.getKey();
            if (isSessionManagedAuthHeader(name)) {
                continue;
            }
            String value = header.getValue();
            validateHeader(name, value);
            sb.append(name).append(": ").append(value).append("\r\n");
        }
        return sb.toString();
    }

    private static boolean isSessionManagedAuthHeader(String name) {
        return AuthHeaders.AUTHORIZATION_HEADER.equalsIgnoreCase(name);
    }

    private void validateHeader(String name, String value) {
        if (name == null || !HEADER_NAME_TOKEN.matcher(name).matches()) {
            throw new IllegalArgumentException("Invalid HTTP header name: " + name);
        }
        if (value == null || containsControlChar(value)) {
            throw new IllegalArgumentException("Invalid HTTP header value for " + name);
        }
    }

    private boolean containsControlChar(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                return true;
            }
        }
        return false;
    }

    private List<InsertionPointOffset> computeArgumentOffsets(byte[] bodyBytes, int bodyStartOffset) {
        Optional<ArgumentsObjectRange> argumentsLocation = ArgumentsObjectLocator.locate(bodyBytes);
        if (argumentsLocation.isEmpty()) {
            return List.of();
        }
        ArgumentsObjectRange range = argumentsLocation.get();
        byte[] argumentsBytes = Arrays.copyOfRange(bodyBytes, range.start(), range.end());
        Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(argumentsBytes);

        List<InsertionPointOffset> offsets = new ArrayList<>();
        for (Map.Entry<String, ValueByteRange> entry : ranges.entrySet()) {
            ValueByteRange valueRange = entry.getValue();
            if (valueRange.kind() != ValueKind.STRING) continue;
            int absoluteStart = bodyStartOffset + range.start() + valueRange.innerStartInclusive();
            int absoluteEnd = bodyStartOffset + range.start() + valueRange.innerEndExclusive();
            offsets.add(new InsertionPointOffset(entry.getKey(), absoluteStart, absoluteEnd));
        }
        return offsets;
    }

    private List<InsertionPointOffset> computeUriOffsets(byte[] bodyBytes, int bodyStartOffset) {
        return UriValueLocator.locate(bodyBytes)
                .map(range -> List.of(new InsertionPointOffset(
                        "uri",
                        bodyStartOffset + range.innerStartInclusive(),
                        bodyStartOffset + range.innerEndExclusive())))
                .orElseGet(List::of);
    }

    private List<InsertionPointOffset> computeTemplateVariableOffsets(byte[] bodyBytes, int bodyStartOffset,
                                                                      UriTemplateExpansion.Result expansion) {
        Optional<UriValueLocator.UriValueRange> uriRangeOpt = UriValueLocator.locate(bodyBytes);
        if (uriRangeOpt.isEmpty()) {
            return List.of();
        }
        int uriContentStartInBody = uriRangeOpt.get().innerStartInclusive();
        List<InsertionPointOffset> offsets = new ArrayList<>(expansion.variables().size());
        for (UriTemplateExpansion.Variable variable : expansion.variables()) {
            offsets.add(new InsertionPointOffset(
                    variable.name(),
                    bodyStartOffset + uriContentStartInBody + variable.startInclusive(),
                    bodyStartOffset + uriContentStartInBody + variable.endExclusive()));
        }
        return offsets;
    }
}
