package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class SimulatedMcpServer {

    public static final String VALID_TOKEN = "Bearer valid-token";
    public static final String ENDPOINT = "http://mcp.example/mcp";
    public static final String SECRET = "s3cr3t-operation-output";
    public static final String CONNECTION_ADDRESS = "10.0.0.5";
    private static final Set<String> ALLOWED_SOURCES = Set.of(CONNECTION_ADDRESS, "127.0.0.1");
    private static final String SOURCE_FORBIDDEN =
            "{\"errorCode\":200020,\"errorMessage\":\"ip address is forbidden to access this resource\"}";

    private boolean authRequired;
    private boolean sessionRequired;
    private boolean sessionAuthenticates;
    private String unguardedPath;
    private String unguardedHeader;
    private String softRefusalText;
    private String operationText;
    private String toolDeniedToBypassCallers;
    private String toolForbiddenToBypassCallers;
    private boolean issuesSessionIds = true;
    private boolean headerValueIgnored;
    private boolean sessionlessRefused;
    private boolean sessionlessServerError;
    private boolean presenceOnly;
    private boolean credentialValidatedUpstream;
    private String extraAcceptedCredential;
    private String toolErrorRefusal;
    private boolean missingCredentialServerError;
    private boolean missingCredentialErrorsVary;
    private int serverErrors;
    private int temporaryAnonymousRefusals;
    private boolean anonymousBlockPage;
    private boolean anonymousPingChallenged;
    private boolean protectedResourceMetadata;
    private boolean liveStreamMessagesUnguarded;
    private boolean unknownCursorsRejected;
    private String publicCatalogPath;
    private String quotaSpentPath;
    private final Map<String, String> cannedAnswers = new HashMap<>();
    private boolean emptyCatalog;
    private boolean appPageFallback;
    private String sourceAddressHeader;
    private boolean forwardedHeadersRejected;
    private boolean forwardedHeadersThrottled;
    private int credentialFailuresBeforeLockout = -1;
    private int sourceRefusalStatus = 400;
    private boolean sourceRefusalsVary;
    private int sourceRefusals;
    private int transientFailureStatus;
    private String transientFailureBody;
    private int requestsSeen;
    private final Set<String> authenticatedSessions = new HashSet<>();
    private final Set<String> issuedSessions = new HashSet<>();
    private final List<HttpRequest> received = new ArrayList<>();
    private int sessionCounter;

    public static SimulatedMcpServer open() {
        return new SimulatedMcpServer();
    }

    public static SimulatedMcpServer enforcing() {
        SimulatedMcpServer server = new SimulatedMcpServer();
        server.authRequired = true;
        return server;
    }

    public SimulatedMcpServer requiringSessions() {
        sessionRequired = true;
        return this;
    }

    public SimulatedMcpServer issuingNoSessionIds() {
        issuesSessionIds = false;
        return this;
    }

    public SimulatedMcpServer authenticatingBySession() {
        sessionAuthenticates = true;
        return this;
    }

    public SimulatedMcpServer withUnguardedPath(String path) {
        unguardedPath = path;
        return this;
    }

    public SimulatedMcpServer trustingHeader(String header) {
        unguardedHeader = header;
        return this;
    }

    public SimulatedMcpServer refusingSessionlessRequests() {
        sessionlessRefused = true;
        return this;
    }

    public SimulatedMcpServer failingWithoutSessions() {
        sessionlessServerError = true;
        return this;
    }

    public SimulatedMcpServer acceptingAnyCredential() {
        presenceOnly = true;
        return this;
    }

    public SimulatedMcpServer passingCredentialsToAValidatingUpstream() {
        credentialValidatedUpstream = true;
        return acceptingAnyCredential();
    }

    public SimulatedMcpServer acceptingCredential(String authorization) {
        extraAcceptedCredential = authorization;
        return this;
    }

    public SimulatedMcpServer refusingWithToolError(String text) {
        toolErrorRefusal = text;
        return this;
    }

    public SimulatedMcpServer failingWithoutCredentials() {
        missingCredentialServerError = true;
        return this;
    }

    public SimulatedMcpServer failingWithoutCredentialsVariably() {
        missingCredentialErrorsVary = true;
        return failingWithoutCredentials();
    }

    public SimulatedMcpServer trustingAnyValue() {
        headerValueIgnored = true;
        return this;
    }

    public SimulatedMcpServer denyingToolToBypassCallers(String toolName) {
        toolDeniedToBypassCallers = toolName;
        return this;
    }

    public SimulatedMcpServer forbiddingToolToBypassCallers(String toolName) {
        toolForbiddenToBypassCallers = toolName;
        return this;
    }

    public SimulatedMcpServer answeringOperationsWith(String text) {
        operationText = text;
        return this;
    }

    public SimulatedMcpServer answeringAnonymousCallersWith(String text) {
        softRefusalText = text;
        return this;
    }

    public SimulatedMcpServer refusingTheFirstAnonymousRequests(int count) {
        temporaryAnonymousRefusals = count;
        return this;
    }

    public SimulatedMcpServer blockingAnonymousCallersWithAPage() {
        anonymousBlockPage = true;
        return this;
    }

    public SimulatedMcpServer challengingAnonymousPing() {
        anonymousPingChallenged = true;
        return this;
    }

    public SimulatedMcpServer simulatingAProxyLiveStreamThatAcceptsAnonymousMessages() {
        liveStreamMessagesUnguarded = true;
        return this;
    }

    public SimulatedMcpServer servingAnUnrelatedPublicCatalogOn(String path) {
        publicCatalogPath = path;
        return withUnguardedPath(path);
    }

    public SimulatedMcpServer answeringPath(String path, int status, String contentType, String body) {
        cannedAnswers.put(path, "HTTP/1.1 " + status + " X\r\nContent-Type: " + contentType + "\r\n\r\n" + body);
        return this;
    }

    public SimulatedMcpServer advertisingASpentRateLimitQuotaOn(String path) {
        quotaSpentPath = path;
        return this;
    }

    public SimulatedMcpServer answeringUnknownPathsWithAnAppPage() {
        appPageFallback = true;
        return this;
    }

    public SimulatedMcpServer listingNoTools() {
        emptyCatalog = true;
        return this;
    }

    public SimulatedMcpServer rejectingUnknownCursors() {
        unknownCursorsRejected = true;
        return this;
    }

    public SimulatedMcpServer advertisingProtectedResourceMetadata() {
        protectedResourceMetadata = true;
        return this;
    }

    public SimulatedMcpServer restrictingSourceAddressesTrusting(String header) {
        sourceAddressHeader = header;
        return this;
    }

    public SimulatedMcpServer rejectingForwardedHeaders() {
        forwardedHeadersRejected = true;
        return this;
    }

    public SimulatedMcpServer refusingSourcesThroughAFailingProxy() {
        sourceRefusalStatus = 502;
        return this;
    }

    public SimulatedMcpServer refusingSourcesThroughAFailingProxyVariably() {
        sourceRefusalsVary = true;
        return refusingSourcesThroughAFailingProxy();
    }

    public SimulatedMcpServer failingEverySecondRequest(int status, String body) {
        transientFailureStatus = status;
        transientFailureBody = body;
        return this;
    }

    public SimulatedMcpServer lockingOutAfterCredentialFailures(int failures) {
        credentialFailuresBeforeLockout = failures;
        return this;
    }

    public SimulatedMcpServer throttlingForwardedHeaders() {
        forwardedHeadersThrottled = true;
        return this;
    }

    public Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> exchange(invocation.getArgument(0)));
        return http;
    }

    public HttpRequestResponse exchange(HttpRequest request) {
        received.add(request);
        String raw = respond(request);
        if (request.pathWithoutQuery().equals(quotaSpentPath)) {
            raw = SpentRateLimitQuota.addedTo(raw);
        }
        return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(raw));
    }

    public List<HttpRequest> received() {
        return List.copyOf(received);
    }

    public String openAuthenticatedSession() {
        String sessionId = newSession();
        authenticatedSessions.add(sessionId);
        return sessionId;
    }

    public static HttpRequest request(String body, Map<String, String> headers) {
        return com.mcpscanner.testutil.ImmutableHttpRequest.post(ENDPOINT, headers, body);
    }

    public static String toolCall() {
        return "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"read_secret\","
                + "\"arguments\":{}}}";
    }

    public static String toolsList() {
        return "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/list\",\"params\":{}}";
    }

    public static String toolsListPage(String cursor) {
        return "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/list\",\"params\":{\"cursor\":\"" + cursor + "\"}}";
    }

    public static String ping() {
        return "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"ping\"}";
    }

    public static String notification() {
        return "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
    }

    private String respond(HttpRequest request) {
        if (transientFailureStatus > 0 && ++requestsSeen % 2 == 0) {
            return raw(transientFailureStatus, transientFailureBody, Map.of());
        }
        if (cannedAnswers.containsKey(request.pathWithoutQuery())) {
            return cannedAnswers.get(request.pathWithoutQuery());
        }
        if (temporaryAnonymousRefusals > 0 && request.headerValue("Authorization") == null) {
            temporaryAnonymousRefusals--;
            return raw(401, "{\"error\":\"unauthorized\"}", Map.of());
        }
        if (protectedResourceMetadata && request.pathWithoutQuery().startsWith("/.well-known/oauth-protected-resource")) {
            return raw(200, "{\"resource\":\"" + ENDPOINT + "\",\"authorization_servers\":[\"http://as.example\"]}",
                    Map.of());
        }
        if (credentialFailuresBeforeLockout == 0) {
            return raw(429, "{\"error\":\"too many failures\"}", Map.of());
        }
        if (credentialFailuresBeforeLockout > 0 && !VALID_TOKEN.equals(request.headerValue("Authorization"))) {
            credentialFailuresBeforeLockout--;
        }
        if (forwardedHeadersThrottled && request.headerValue("X-Forwarded-For") != null) {
            return raw(429, "{\"error\":\"too many requests\"}", Map.of());
        }
        if (forwardedHeadersRejected && request.headerValue("X-Forwarded-For") != null) {
            return raw(400, "{\"error\":\"forwarding headers are not accepted\"}", Map.of());
        }
        if (sourceAddressHeader != null && !ALLOWED_SOURCES.contains(sourceAddress(request))) {
            sourceRefusals++;
            return raw(sourceRefusalStatus, sourceRefusalsVary ? SOURCE_FORBIDDEN + sourceRefusals : SOURCE_FORBIDDEN,
                    Map.of());
        }
        boolean onEndpoint = "/mcp".equals(request.pathWithoutQuery());
        boolean onUnguardedPath = request.pathWithoutQuery().equals(unguardedPath);
        if (!onEndpoint && !onUnguardedPath) {
            return appPageFallback
                    ? "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!doctype html><html><body>app</body></html>"
                    : raw(404, "{\"error\":\"not found\"}", Map.of());
        }
        JsonNode message = parse(request.bodyToString());
        String sessionId = request.headerValue("Mcp-Session-Id");
        String authorization = request.headerValue("Authorization");
        boolean authenticated = VALID_TOKEN.equals(authorization)
                || presenceOnly && authorization != null && !authorization.isBlank()
                || authorization != null && authorization.equals(extraAcceptedCredential)
                || onUnguardedPath
                || liveStreamMessagesUnguarded && request.hasHeader(ScannerSentinels.KEEP_SESSION_HEADER)
                || unguardedHeader != null && request.headerValue(unguardedHeader) != null
                && (headerValueIgnored || "127.0.0.1".equals(request.headerValue(unguardedHeader)))
                || sessionAuthenticates && sessionId != null && authenticatedSessions.contains(sessionId);
        if ("ping".equals(message.path("method").asText()) && anonymousPingChallenged && authorization == null) {
            return raw(401, "{\"error\":\"unauthorized\"}", Map.of("WWW-Authenticate", "Bearer realm=\"mcp\""));
        }
        if (authRequired && !authenticated) {
            Optional<String> refusal = refusal(message, authorization);
            if (refusal.isPresent()) {
                return refusal.get();
            }
        }
        if ("initialize".equals(message.path("method").asText())) {
            return reply(message, initializeResult(),
                    issuesSessionIds ? Map.of("Mcp-Session-Id", newSession()) : Map.of());
        }
        if (sessionRequired && sessionId != null && !issuedSessions.contains(sessionId)) {
            return raw(404, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,\"message\":\"Session not found\"}}",
                    Map.of());
        }
        if (sessionRequired && sessionId == null && sessionlessRefused) {
            return raw(401, "{\"error\":\"Unauthorized: Session ID is required\"}", Map.of());
        }
        if (sessionRequired && sessionId == null && sessionlessServerError) {
            return raw(500, "{\"error\":\"Internal Server Error\"}", Map.of());
        }
        if (sessionRequired && sessionId == null) {
            return raw(400, "{\"error\":\"Bad Request: Missing session ID\"}", Map.of());
        }
        if (!message.has("id")) {
            return raw(202, "", Map.of());
        }
        if (unknownCursorsRejected && message.path("params").has("cursor")) {
            return raw(200, "{\"jsonrpc\":\"2.0\",\"id\":" + message.get("id")
                    + ",\"error\":{\"code\":-32602,\"message\":\"invalid cursor\"}}", Map.of());
        }
        boolean anonymous = request.headerValue("Authorization") == null;
        if (anonymous && message.path("params").path("name").asText().equals(toolForbiddenToBypassCallers)) {
            return raw(403, "{\"error\":\"tool forbidden for this principal\"}", Map.of());
        }
        if (anonymous && message.path("params").path("name").asText().equals(toolDeniedToBypassCallers)) {
            return reply(message, deniedToolResult(), Map.of());
        }
        if (credentialValidatedUpstream && "tools/call".equals(message.path("method").asText())
                && !VALID_TOKEN.equals(authorization)) {
            return reply(message, toolError("Upstream API rejected the request: invalid API key"), Map.of());
        }
        if (request.pathWithoutQuery().equals(publicCatalogPath)) {
            return reply(message, publicCatalog(), Map.of());
        }
        return reply(message, resultFor(message.path("method").asText(), anonymous), Map.of());
    }

    private static ObjectNode publicCatalog() {
        ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode();
        result.putArray("tools").addObject().put("name", "public_weather");
        return result;
    }

    private Optional<String> refusal(JsonNode message, String authorization) {
        String method = message.path("method").asText();
        if (anonymousBlockPage && authorization == null) {
            return Optional.of(raw(403, "<html><body>Request blocked</body></html>", Map.of()));
        }
        if (missingCredentialServerError && authorization == null) {
            serverErrors++;
            String details = missingCredentialErrorsVary ? "request " + serverErrors : "";
            return Optional.of(raw(500, "{\"error\":\"MCP request failed\",\"details\":\"" + details + "\"}",
                    Map.of()));
        }
        if (toolErrorRefusal == null) {
            return Optional.of(raw(401, "{\"error\":\"unauthorized\"}", Map.of()));
        }
        if ("tools/call".equals(method)) {
            return Optional.of(reply(message, toolError(toolErrorRefusal), Map.of()));
        }
        return "initialize".equals(method) || !message.has("id")
                ? Optional.empty() : Optional.of(raw(401, "{\"error\":\"unauthorized\"}", Map.of()));
    }

    private String sourceAddress(HttpRequest request) {
        String claimed = request.headerValue(sourceAddressHeader);
        return claimed == null ? CONNECTION_ADDRESS : claimed;
    }

    private String newSession() {
        sessionCounter++;
        issuedSessions.add("session-" + sessionCounter);
        return "session-" + sessionCounter;
    }

    private ObjectNode resultFor(String method, boolean anonymous) {
        ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode();
        if ("tools/list".equals(method)) {
            if (emptyCatalog) {
                result.putArray("tools");
            } else {
                result.putArray("tools").addObject().put("name", "read_secret");
            }
        } else if ("tools/call".equals(method)) {
            String text = anonymous && softRefusalText != null ? softRefusalText
                    : operationText != null ? operationText : SECRET;
            result.putArray("content").addObject().put("type", "text").put("text", text);
            result.put("isError", false);
        }
        return result;
    }

    private static ObjectNode deniedToolResult() {
        return toolError("Permission denied");
    }

    private static ObjectNode toolError(String text) {
        ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode();
        result.putArray("content").addObject().put("type", "text").put("text", text);
        result.put("isError", true);
        return result;
    }

    public static String toolCallOf(String toolName) {
        return "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"tools/call\",\"params\":{\"name\":\"" + toolName
                + "\",\"arguments\":{}}}";
    }

    private static ObjectNode initializeResult() {
        ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode().put("protocolVersion", "2025-06-18");
        result.putObject("capabilities");
        result.putObject("serverInfo").put("name", "simulated").put("version", "1");
        return result;
    }

    private static String reply(JsonNode message, ObjectNode result, Map<String, String> headers) {
        ObjectNode reply = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0");
        reply.set("id", message.get("id"));
        reply.set("result", result);
        return raw(200, reply.toString(), headers);
    }

    private static String raw(int status, String body, Map<String, String> headers) {
        StringBuilder raw = new StringBuilder("HTTP/1.1 ").append(status).append(" X\r\n")
                .append("Content-Type: application/json\r\n");
        headers.forEach((name, value) -> raw.append(name).append(": ").append(value).append("\r\n"));
        return raw.append("\r\n").append(body).toString();
    }

    private static JsonNode parse(String body) {
        try {
            return McpObjectMapper.INSTANCE.readTree(body == null || body.isBlank() ? "{}" : body);
        } catch (Exception unparseable) {
            return McpObjectMapper.INSTANCE.createObjectNode();
        }
    }
}
