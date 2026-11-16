package com.mcpscanner.integration;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.client.McpDiscoveryClient;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.proxy.SseProxyServer;
import com.mcpscanner.scan.McpRepeaterRequestFactory;
import com.mcpscanner.scan.ScanSession;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.scan.field.TemplateExpansionRegistry;
import com.mcpscanner.scan.request.ClientRegistrationRequestFactory;
import com.mcpscanner.scan.request.McpHttpRequestFactory;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import com.mcpscanner.scan.request.ScanRequestRenderer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Timeout(30)
class AuthenticatedTransportIT {
    private static final String AUTHORIZATION = "Bearer local-fixture-token";
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final Logging logging = mock(Logging.class);

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
        when(ObjectFactoryLocator.FACTORY.httpRequest(any(HttpService.class), anyString()))
                .thenAnswer(invocation -> mockRequest(invocation.getArgument(1)));
    }

    private HttpRequest mockRequest(String raw) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.toString()).thenReturn(raw);
        var headers = new java.util.ArrayList<burp.api.montoya.http.message.HttpHeader>();
        for (String line : raw.split("\r\n\r\n", 2)[0].split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            var header = mock(burp.api.montoya.http.message.HttpHeader.class);
            when(header.name()).thenReturn(line.substring(0, colon));
            when(header.value()).thenReturn(line.substring(colon + 1).trim());
            headers.add(header);
        }
        when(request.headers()).thenReturn(headers);
        when(request.withAddedHeader(anyString(), anyString())).thenAnswer(invocation -> mockRequest(
                raw.replace("\r\n\r\n", "\r\n" + invocation.getArgument(0) + ": "
                        + invocation.getArgument(1) + "\r\n\r\n")));
        return request;
    }

    @ParameterizedTest
    @MethodSource("protocols")
    void bearerProtectsConnectionCatalogAndEquivalentScanAndRepeaterOperations(TransportType transport, String version)
            throws Exception {
        try (ProtectedServer server = new ProtectedServer(transport, version)) {
            McpScannerSession anonymous = newSession();
            assertThatThrownBy(() -> anonymous.connect(new McpServerConfig(
                    server.endpoint(), transport, new NoAuthStrategy())))
                    .isInstanceOf(IllegalStateException.class);
            assertThat(server.denied).isNotEmpty().allMatch(request -> request.authorization() == null);

            McpScannerSession session = newSession();
            SseProxyServer proxy = com.mcpscanner.proxy.TestSseProxies.builder(session).build();
            try {
                session.connect(new McpServerConfig(server.endpoint(), transport,
                        new BearerTokenAuthStrategy("local-fixture-token")));
                assertThat(session.transportType()).isEqualTo(transport);
                McpDiscoveryClient discovery = new McpDiscoveryClient(session);
                var tools = discovery.discoverTools();
                var resources = discovery.discoverResources();
                assertThat(tools).extracting(tool -> tool.name()).containsExactly("protected_echo");
                assertThat(resources).extracting(resource -> resource.uri()).containsExactly("fixture://protected");

                proxy.start();
                ScanMessageRenderer renderer = renderer(session);
                String scan = managedScan(proxy, session, renderer);
                String repeater = new McpRepeaterRequestFactory(
                        ScanSession.of(session::resolvedEndpoint, session::scannerHeaders), RequestGenerator.standard(),
                        renderer, proxy::captureScanConnection).requestFor(new ScanTarget.Tool(tools.get(0))).toString();
                assertThat(scan).doesNotContain("Authorization:");
                assertThat(repeater).doesNotContain("Authorization:");

                assertProtectedReply(postRaw(proxy.port(), scan));
                assertProtectedReply(postRaw(proxy.port(), repeater));
                String manual = repeater.replace("\r\n\r\n", "\r\nAuthorization: " + AUTHORIZATION + "\r\n\r\n");
                assertProtectedReply(postRaw(proxy.port(), manual));
                List<CapturedRequest> operations = server.accepted.stream()
                        .filter(request -> request.method().equals("tools/call")).toList();
                assertThat(operations).hasSize(3);
                assertThat(operations.get(0).transportHeaders()).isEqualTo(operations.get(1).transportHeaders());
                assertThat(operations).allSatisfy(request -> {
                    assertThat(request.authorization()).isEqualTo(AUTHORIZATION);
                    assertThat(request.transportHeaders()).containsEntry("mcp-protocol-version", server.version());
                });
                if (transport == TransportType.MODERN_HTTP) {
                    assertThat(operations.get(0).transportHeaders()).containsEntry("mcp-method", "tools/call")
                            .containsEntry("mcp-name", "protected_echo").doesNotContainKey("mcp-session-id");
                } else if (transport == TransportType.STREAMABLE_HTTP) {
                    assertThat(operations.get(0).transportHeaders()).containsEntry("mcp-session-id", "fixture-session");
                } else {
                    assertThat(operations.get(0).transportHeaders()).doesNotContainKey("mcp-session-id");
                }
                assertThat(server.accepted).allSatisfy(request ->
                        assertThat(request.authorization()).isEqualTo(AUTHORIZATION));
                String edited = repeater.replace("\r\n\r\n", "\r\nAuthorization: Bearer identity-B\r\n\r\n");
                assertThat(postRaw(proxy.port(), edited).statusCode()).isEqualTo(401);
                assertThat(server.denied.get(server.denied.size() - 1).authorization()).isEqualTo("Bearer identity-B");
                String unmarked = repeater.replaceAll("(?im)^X-Mcp-Scanner-Audit-Capability:[^\r\n]*\r\n", "");
                assertThat(postRaw(proxy.port(), unmarked).statusCode()).isEqualTo(401);
                assertThat(server.denied.get(server.denied.size() - 1).authorization()).isNull();
                String stripped = repeater.replace("\r\n\r\n", "\r\nX-Mcp-Scanner-Strip-Auth: 1\r\n\r\n");
                assertThat(postRaw(proxy.port(), stripped).statusCode()).isEqualTo(401);
                assertThat(server.denied.get(server.denied.size() - 1).authorization()).isNull();
                assertAnonymousOperationsDenied(session, server);
                session.disconnect();
                session.connect(new McpServerConfig(server.endpoint(), transport,
                        new BearerTokenAuthStrategy("local-fixture-token")));
                int requestsBeforeRetired = server.accepted.size() + server.denied.size();
                assertThat(postRaw(proxy.port(), repeater).statusCode()).isEqualTo(409);
                assertThat(server.accepted.size() + server.denied.size()).isEqualTo(requestsBeforeRetired);
            } finally {
                proxy.stop();
                session.disconnect();
            }
        }
    }

    @ParameterizedTest
    @MethodSource("protocols")
    void editedInertCustomCredentialCannotExecuteAsConnectedIdentity(TransportType transport, String version)
            throws Exception {
        try (ProtectedServer server = new ProtectedServer(transport, version, "User-Agent", "identity-A")) {
            McpScannerSession session = newSession();
            SseProxyServer proxy = com.mcpscanner.proxy.TestSseProxies.builder(session).build();
            try {
                session.connect(new McpServerConfig(server.endpoint(), transport,
                        new com.mcpscanner.auth.CustomHeaderAuthStrategy(Map.of("User-Agent", "identity-A"))));
                proxy.start();
                var tool = new com.mcpscanner.mcp.McpToolDefinition("protected_echo", "fixture", "{}");
                String repeater = new McpRepeaterRequestFactory(
                        ScanSession.of(session::resolvedEndpoint, session::scannerHeaders), RequestGenerator.standard(),
                        renderer(session), proxy::captureScanConnection)
                        .requestFor(new ScanTarget.Tool(tool)).toString();
                assertProtectedReply(postRaw(proxy.port(), repeater));
                int acceptedOperations = (int) server.accepted.stream()
                        .filter(request -> request.method().equals("tools/call")).count();

                String edited = repeater.replace("User-Agent: identity-A", "User-Agent: identity-B");
                assertThat(postRaw(proxy.port(), edited).statusCode()).isEqualTo(401);
                assertThat(server.denied.get(server.denied.size() - 1).authorization()).isEqualTo("identity-B");
                String removed = repeater.replaceAll("(?im)^User-Agent:[^\r\n]*\r\n", "");
                assertThat(postRaw(proxy.port(), removed).statusCode()).isEqualTo(401);
                assertThat(server.denied.get(server.denied.size() - 1).authorization()).isNotEqualTo("identity-A");
                assertThat(server.accepted.stream().filter(request -> request.method().equals("tools/call")))
                        .hasSize(acceptedOperations);
            } finally {
                proxy.stop();
                session.disconnect();
            }
        }
    }

    static java.util.stream.Stream<Arguments> protocols() {
        return java.util.stream.Stream.of(
                Arguments.of(TransportType.MODERN_HTTP, "2026-07-28"),
                Arguments.of(TransportType.STREAMABLE_HTTP, "2025-11-25"),
                Arguments.of(TransportType.STREAMABLE_HTTP, "2025-06-18"),
                Arguments.of(TransportType.STREAMABLE_HTTP, "2025-03-26"),
                Arguments.of(TransportType.SSE, "2024-11-05"));
    }

    private static ScanMessageRenderer renderer(McpScannerSession session) {
        return new ScanRequestRenderer(new McpHttpRequestFactory(session::nextRequestId, session)::build,
                new ClientRegistrationRequestFactory());
    }

    private String managedScan(SseProxyServer proxy, McpScannerSession session, ScanMessageRenderer renderer) {
        var scanner = mock(burp.api.montoya.scanner.Scanner.class);
        var audit = mock(burp.api.montoya.scanner.audit.Audit.class);
        when(scanner.startAudit(any())).thenReturn(audit);
        var launcher = new com.mcpscanner.scan.McpScanLauncher(logging, renderer, proxy::captureScanConnection,
                new TemplateExpansionRegistry(), com.mcpscanner.scan.ScanDestinations.of(scanner, mock(burp.api.montoya.burpsuite.BurpSuite.class, org.mockito.Answers.RETURNS_DEEP_STUBS), McpEventLog.noop(),
                        new com.mcpscanner.scan.EngineScans(mock(com.mcpscanner.engine.McpScanEngine.class),
                                new com.mcpscanner.scan.ScanLabels(com.mcpscanner.scan.FixedConnectionFacts.NONE,
                                        new com.mcpscanner.mcp.McpRequestNames())), () -> { }),
                new com.mcpscanner.scan.RunningScans(McpEventLog.noop(),
                        mock(burp.api.montoya.burpsuite.BurpSuite.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));
        var tool = new com.mcpscanner.mcp.McpToolDefinition("protected_echo", "fixture",
                "{\"type\":\"object\",\"properties\":{\"message\":{\"type\":\"string\"}}}");
        launcher.captureScan(com.mcpscanner.scan.ScanMode.MCP_AND_BURP, session.resolvedEndpoint(),
                RequestGenerator.standard().scanThisRequest(RequestFamily.TOOLS_CALL,
                        com.mcpscanner.scan.ScanInventory.toolsOnly(List.of(tool))),
                session::scannerHeaders, launcher.captureConnection()).get();
        var request = org.mockito.ArgumentCaptor.forClass(HttpRequest.class);
        org.mockito.Mockito.verify(audit).addRequest(request.capture());
        return request.getValue().toString();
    }

    private McpScannerSession newSession() {
        return new McpScannerSession(http, McpEventLog.noop());
    }

    private void assertAnonymousOperationsDenied(McpScannerSession session, ProtectedServer server) throws Exception {
        for (String method : List.of("tools/list", "resources/list", "tools/call")) {
            String params = method.equals("tools/call") ? "{\"name\":\"protected_echo\",\"arguments\":{}}" : "{}";
            var framed = session.operation(method, params, session.nextRequestId());
            var request = java.net.http.HttpRequest.newBuilder(URI.create(session.resolvedEndpoint()))
                    .timeout(Duration.ofSeconds(3)).POST(java.net.http.HttpRequest.BodyPublishers.ofString(framed.body()));
            framed.headers().forEach(request::header);
            assertThat(http.send(request.build(), HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
        }
        assertThat(server.denied).extracting(CapturedRequest::method)
                .contains("tools/list", "resources/list", "tools/call");
    }

    private HttpResponse<String> postRaw(int proxyPort, String raw) throws Exception {
        String[] parts = raw.split("\r\n\r\n", 2);
        String path = parts[0].split(" ")[1];
        var builder = java.net.http.HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxyPort + path))
                .timeout(Duration.ofSeconds(8)).POST(java.net.http.HttpRequest.BodyPublishers.ofString(parts[1]));
        for (String line : parts[0].split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) continue;
            String name = line.substring(0, colon);
            if (!name.equalsIgnoreCase("Host") && !name.equalsIgnoreCase("Content-Length")) {
                builder.header(name, line.substring(colon + 1).trim());
            }
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void assertProtectedReply(HttpResponse<String> response) throws IOException {
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode reply = McpObjectMapper.INSTANCE.readTree(response.body());
        assertThat(reply.path("result").path("content").get(0).path("text").asText())
                .isEqualTo("protected-fixture-result");
    }

    private record CapturedRequest(String method, String authorization, Map<String, String> transportHeaders) {}

    private static final class ProtectedServer implements AutoCloseable {
        private final HttpServer server;
        private final TransportType transport;
        private final String version;
        private final String credentialHeader;
        private final String credentialValue;
        private final List<CapturedRequest> accepted = new CopyOnWriteArrayList<>();
        private final List<CapturedRequest> denied = new CopyOnWriteArrayList<>();
        private final Map<String, OutputStream> streams = new ConcurrentHashMap<>();
        private final AtomicInteger streamIds = new AtomicInteger();

        private ProtectedServer(TransportType transport, String version) throws IOException {
            this(transport, version, "Authorization", AUTHORIZATION);
        }

        private ProtectedServer(TransportType transport, String version, String credentialHeader,
                                String credentialValue) throws IOException {
            this.credentialHeader = credentialHeader;
            this.credentialValue = credentialValue;
            this.transport = transport;
            this.version = version;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.start();
        }

        private String endpoint() {
            return "http://127.0.0.1:" + server.getAddress().getPort() + (transport == TransportType.SSE ? "/sse" : "/mcp");
        }

        private String version() {
            return version;
        }

        private void handle(HttpExchange exchange) throws IOException {
            JsonNode body = exchange.getRequestMethod().equals("POST")
                    ? McpObjectMapper.INSTANCE.readTree(exchange.getRequestBody()) : null;
            String method = body == null ? exchange.getRequestMethod() : body.path("method").asText();
            Map<String, String> headers = new TreeMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> {
                if (name.toLowerCase(java.util.Locale.ROOT).startsWith("mcp-")) {
                    headers.put(name.toLowerCase(java.util.Locale.ROOT), String.join(",", values));
                }
            });
            String authorization = exchange.getRequestHeaders().getFirst(credentialHeader);
            CapturedRequest captured = new CapturedRequest(method, authorization, Map.copyOf(headers));
            if (!credentialValue.equals(authorization)) {
                denied.add(captured);
                exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer realm=\"local-fixture\"");
                respond(exchange, 401, "{\"error\":\"unauthorized\"}");
                return;
            }
            accepted.add(captured);
            if (transport == TransportType.SSE && method.equals("GET")) {
                String id = Integer.toString(streamIds.incrementAndGet());
                exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
                exchange.sendResponseHeaders(200, 0);
                OutputStream stream = exchange.getResponseBody();
                streams.put(id, stream);
                writeEvent(stream, "endpoint", "/messages?stream=" + id);
                return;
            }
            if (method.equals("DELETE") || method.equals("notifications/initialized")) {
                respond(exchange, 202, "");
                return;
            }
            if (!validTransportHeaders(method, headers)) {
                respond(exchange, 400, "{\"error\":\"invalid transport headers\"}");
                return;
            }
            String reply = McpObjectMapper.INSTANCE.writeValueAsString(Map.of(
                    "jsonrpc", "2.0", "id", body.path("id").asLong(), "result", result(method)));
            if (transport == TransportType.SSE) {
                OutputStream stream = streams.get(exchange.getRequestURI().getRawQuery().substring("stream=".length()));
                writeEvent(stream, "message", reply);
                respond(exchange, 202, "");
            } else {
                if (method.equals("initialize")) exchange.getResponseHeaders().set("Mcp-Session-Id", "fixture-session");
                respond(exchange, 200, reply);
            }
        }

        private boolean validTransportHeaders(String method, Map<String, String> headers) {
            if (method.equals("initialize")) return true;
            if (!version().equals(headers.get("mcp-protocol-version"))) return false;
            if (transport == TransportType.MODERN_HTTP) {
                return method.equals(headers.get("mcp-method"))
                        && (!method.equals("tools/call") || "protected_echo".equals(headers.get("mcp-name")));
            }
            return transport != TransportType.STREAMABLE_HTTP || method.equals("initialize")
                    || "fixture-session".equals(headers.get("mcp-session-id"));
        }

        private Map<String, Object> result(String method) {
            return switch (method) {
                case "server/discover" -> Map.of("supportedVersions", List.of(version()), "capabilities", Map.of());
                case "initialize" -> Map.of("protocolVersion", version(), "capabilities", Map.of("tools", Map.of(), "resources", Map.of()),
                        "serverInfo", Map.of("name", "protected-fixture", "version", "1"));
                case "tools/list" -> Map.of("tools", List.of(Map.of("name", "protected_echo", "inputSchema", Map.of("type", "object", "properties", Map.of()))));
                case "resources/list" -> Map.of("resources", List.of(Map.of("name", "protected", "uri", "fixture://protected")));
                case "tools/call" -> Map.of("content", List.of(Map.of("type", "text", "text", "protected-fixture-result")));
                default -> throw new IllegalArgumentException(method);
            };
        }

        private void writeEvent(OutputStream stream, String event, String data) throws IOException {
            stream.write(("event: " + event + "\ndata: " + data + "\n\n").getBytes(StandardCharsets.UTF_8));
            stream.flush();
        }

        private void respond(HttpExchange exchange, int status, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(bytes);
            }
        }

        @Override
        public void close() throws IOException {
            for (OutputStream stream : streams.values()) stream.close();
            server.stop(0);
        }
    }
}
