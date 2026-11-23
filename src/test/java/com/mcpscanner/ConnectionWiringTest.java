package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import com.mcpscanner.client.BurpNetworkingSetting;
import burp.api.montoya.MontoyaApi;
import com.mcpscanner.testutil.RecordingRequestOptions;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.http.UpstreamEvidence;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.auth.AccessToken;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.BurpEmptyResponse;
import com.mcpscanner.testutil.FakeMcpServer;
import com.mcpscanner.testutil.IdentityProbes;
import com.mcpscanner.testutil.LoopbackFakeMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.PlaintextReplyListener;
import com.mcpscanner.testutil.ScanProxyClient;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConnectionWiringTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final String USE_BURP_NETWORKING = "mcp.networking.use_burp";
    private static final String SESSION_TOKEN = "session-token";
    private static final String FUZZED_PROTOCOL_VERSION = "1999-01-01";

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Http http = mock(Http.class);
    private final PersistedObject savedSettings = mock(PersistedObject.class);
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();
    private final ShutdownHooks shutdown = new ShutdownHooks(failure -> {
        throw new AssertionError(failure);
    });
    private ExtensionFoundation foundation;
    private ConnectionWiring wiring;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        when(api.http()).thenReturn(http);
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(null);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
        foundation = ExtensionFoundation.create(api);
        wiring = ConnectionWiring.create(api, foundation);
    }

    @AfterEach
    void unload() {
        shutdown.extensionUnloaded();
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void clientManagerSendsHttpTransportConnectTrafficThroughBurp(TransportType transport) {
        wiring.start(shutdown);

        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, transport, new NoAuthStrategy()));

        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/list")), any(RequestOptions.class));
    }

    @Test
    void connectClosesItsFirstConnectionThenReusesOneSharedHttp1Connection() {
        wiring.start(shutdown);

        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP, new NoAuthStrategy()));

        List<RecordingRequestOptions> sends = sentOptions();
        assertThat(sends.get(0).connectionId()).isEmpty();
        assertThat(sends.subList(1, sends.size())).isNotEmpty().allSatisfy(options -> {
            assertThat(options.httpMode()).contains(HttpMode.HTTP_1);
            assertThat(options.connectionId()).isPresent();
        });
    }

    @Test
    void disconnectForgetsWhichOriginsKeepConnectionsAlive() {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP, new NoAuthStrategy()));
        wiring.clientManager().disconnect();
        int sentBeforeReconnect = sentOptions().size();

        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP, new NoAuthStrategy()));

        assertThat(sentOptions().get(sentBeforeReconnect).connectionId()).isEmpty();
    }

    @Test
    void resendsAReadOnAFreshConnectionWhenItsKeptAliveConnectionWasClosedWhileQueued() {
        int sentBefore = connectedThenKeptAliveConnectionsClosed();

        wiring.burpHttp().sendRequest(postedToEndpoint("tools/list", "{}"), RequestOptions.requestOptions());

        assertThat(sentOptions().subList(sentBefore, sentOptions().size()))
                .extracting(options -> options.connectionId().isPresent()).containsExactly(true, false);
    }

    @Test
    void neverResendsACallToAToolThatMayWriteWhenItsKeptAliveConnectionWasClosedWhileQueued() {
        int sentBefore = connectedThenKeptAliveConnectionsClosed();

        wiring.burpHttp().sendRequest(postedToEndpoint("tools/call", "{\"name\":\"echo\"}"),
                RequestOptions.requestOptions());

        assertThat(sentOptions()).hasSize(sentBefore + 1);
    }

    private int connectedThenKeptAliveConnectionsClosed() {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP, new NoAuthStrategy()));
        HttpRequestResponse closedWhileQueued = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(ENDPOINT), BurpEmptyResponse.create());
        when(http.sendRequest(any(HttpRequest.class),
                argThat((RequestOptions options) -> options != null
                        && RecordingRequestOptions.recorded(options).connectionId().isPresent())))
                .thenReturn(closedWhileQueued);
        return sentOptions().size();
    }

    private static HttpRequest postedToEndpoint(String method, String params) {
        return HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"" + method + "\",\"params\":" + params + "}");
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void scanProxySendsScannerTrafficUpstreamThroughBurpWithoutScannerSentinels(TransportType transport)
            throws Exception {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, transport, new NoAuthStrategy()));

        int status = ScanProxyClient.sendScannerToolsCall(wiring.sseProxy().port(), "echo").statusCode();

        assertThat(status).isEqualTo(200);
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call") && carriesNoSentinel(request)),
                any(RequestOptions.class));
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void issueEvidenceFromAProxiedProbeShowsTheExchangeTheTargetSaw(TransportType transport) throws Exception {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, transport, new NoAuthStrategy()));
        java.net.http.HttpResponse<String> proxiedReply =
                ScanProxyClient.sendScannerToolsCall(wiring.sseProxy().port(), "echo");

        AuditIssue translated = new UpstreamEvidence(wiring.upstreamExchanges())
                .translate(issueCiting(proxiedExchange(wiring.sseProxy().port(), proxiedReply)));

        ArgumentCaptor<HttpRequest> sentThroughBurp = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http, atLeastOnce()).sendRequest(sentThroughBurp.capture(), any(RequestOptions.class));
        HttpRequest upstreamToolCall = sentThroughBurp.getAllValues().stream()
                .filter(request -> isCallTo(request, "tools/call")).reduce((first, last) -> last).orElseThrow();
        HttpRequestResponse evidence = translated.requestResponses().get(0);
        assertThat(evidence.request().url()).isEqualTo(ENDPOINT);
        assertThat(carriesNoSentinel(evidence.request())).isTrue();
        assertThat(evidence.request().bodyToString()).isEqualTo(upstreamToolCall.bodyToString());
        assertThat(evidence.response().bodyToString()).contains("\"result\"")
                .contains("\"id\":" + idOf(upstreamToolCall.bodyToString()));
        assertThat(translated.baseUrl()).isEqualTo(ENDPOINT);
    }

    private static String idOf(String body) throws Exception {
        return com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(body).path("id").toString();
    }

    private static HttpRequestResponse proxiedExchange(int proxyPort, java.net.http.HttpResponse<String> reply) {
        String exchangeId = reply.headers().firstValue(ScannerSentinels.EXCHANGE_HEADER).orElseThrow();
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("http://127.0.0.1:" + proxyPort + "/mcp"),
                HttpResponse.httpResponse("HTTP/1.1 " + reply.statusCode() + "\r\n"
                        + ScannerSentinels.EXCHANGE_HEADER + ": " + exchangeId + "\r\n\r\n" + reply.body()));
    }

    private static AuditIssue issueCiting(HttpRequestResponse evidence) {
        return AuditIssue.auditIssue("Name", "Detail", "Remediation", evidence.request().url(),
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Remediation",
                AuditIssueSeverity.HIGH, List.of(evidence));
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void clientManagerSendsConnectTrafficThroughTheJdkClientWhenBurpNetworkingIsOff(TransportType transport)
            throws Exception {
        wiring.start(shutdown);
        when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(false);

        try (LoopbackFakeMcpServer server = LoopbackFakeMcpServer.start()) {
            wiring.clientManager().connect(new McpServerConfig(server.endpoint(), transport, new NoAuthStrategy()));

            assertThat(server.methods()).contains("tools/list");
        }
        verify(http, never()).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void scanProxySendsScannerTrafficUpstreamThroughTheJdkClientWhenBurpNetworkingIsOff(TransportType transport)
            throws Exception {
        wiring.start(shutdown);
        when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(false);

        try (LoopbackFakeMcpServer server = LoopbackFakeMcpServer.start()) {
            wiring.clientManager().connect(new McpServerConfig(server.endpoint(), transport, new NoAuthStrategy()));

            int status = ScanProxyClient.sendScannerToolsCall(wiring.sseProxy().port(), "echo").statusCode();

            assertThat(status).isEqualTo(200);
            assertThat(server.methods()).contains("tools/call");
        }
        verify(http, never()).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    @Test
    void sharedBurpTransportNeverSendsScannerSentinelsThroughBurp() throws Exception {
        wiring.upstreamTransport().send(new ProtocolHttpRequest(URI.create(ENDPOINT), "POST", Map.of(
                        ScannerSentinels.STRIP_AUTH_HEADER, "1",
                        ScannerSentinels.AUDIT_CAPABILITY_HEADER, "capability",
                        "Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"), Duration.ofSeconds(5)).close();

        verify(http).sendRequest(argThat(ConnectionWiringTest::carriesNoSentinel), any(RequestOptions.class));
    }

    @Test
    void sharedBurpTransportIsClosedWhenTheExtensionUnloads() {
        wiring.start(shutdown);

        shutdown.extensionUnloaded();

        assertThatThrownBy(() -> wiring.upstreamTransport().send(new ProtocolHttpRequest(URI.create(ENDPOINT),
                "POST", Map.of(), "{}"), Duration.ofSeconds(5)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("closed");
        verify(http, never()).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    @Test
    void sseTlsHintFollowsTheBurpNetworkingSetting() throws Exception {
        wiring.start(shutdown);
        when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(false);

        try (PlaintextReplyListener notTls = PlaintextReplyListener.start()) {
            assertThatThrownBy(() -> wiring.clientManager().connect(
                    new McpServerConfig(notTls.httpsEndpoint(), TransportType.SSE, new NoAuthStrategy())))
                    .isInstanceOf(RuntimeException.class);
        }

        assertThat(foundation.eventLog().snapshot())
                .anyMatch(entry -> entry.message().contains("turn on \"" + BurpNetworkingSetting.NAME + "\""));
    }

    @Test
    void unloadEndsTheStreamableSessionThroughBurpBeforeClosingTheBurpTransport() {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP,
                new NoAuthStrategy()));

        shutdown.extensionUnloaded();

        verify(http).sendRequest(argThat(request -> "DELETE".equals(request.method())
                        && FakeMcpServer.SESSION_ID.equals(request.headerValue("Mcp-Session-Id"))),
                any(RequestOptions.class));
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void turningBurpNetworkingOffMidConnectionSendsTheNextScannerRequestThroughTheJdkClient(TransportType transport)
            throws Exception {
        wiring.start(shutdown);

        try (LoopbackFakeMcpServer server = LoopbackFakeMcpServer.start()) {
            wiring.clientManager().connect(new McpServerConfig(server.endpoint(), transport, new NoAuthStrategy()));
            when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(false);

            int status = ScanProxyClient.sendScannerToolsCall(wiring.sseProxy().port(), "echo").statusCode();

            assertThat(status).isEqualTo(200);
            assertThat(server.methods()).contains("tools/call");
        }
        verify(http, never()).sendRequest(argThat(request -> carriesCall(request, "tools/call")),
                any(RequestOptions.class));
        assertThat(foundation.eventLog().snapshot())
                .filteredOn(entry -> entry.message().startsWith("Burp networking turned off"))
                .hasSize(1);
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void turningBurpNetworkingOnMidConnectionSendsTheNextScannerRequestThroughBurp(TransportType transport)
            throws Exception {
        wiring.start(shutdown);
        when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(false);

        try (LoopbackFakeMcpServer server = LoopbackFakeMcpServer.start()) {
            wiring.clientManager().connect(new McpServerConfig(server.endpoint(), transport, new NoAuthStrategy()));
            when(savedSettings.getBoolean(USE_BURP_NETWORKING)).thenReturn(true);

            int status = ScanProxyClient.sendScannerToolsCall(wiring.sseProxy().port(), "echo").statusCode();

            assertThat(status).isEqualTo(200);
            assertThat(server.methods()).doesNotContain("tools/call");
        }
        verify(http).sendRequest(argThat(request -> carriesCall(request, "tools/call")), any(RequestOptions.class));
        assertThat(foundation.eventLog().snapshot())
                .filteredOn(entry -> entry.message().startsWith("Burp networking turned on"))
                .hasSize(1);
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void managedScannerRequestReachesBurpWithTheSessionCredentialsAndWithoutScannerSentinels(TransportType transport)
            throws Exception {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, transport,
                new BearerTokenAuthStrategy(SESSION_TOKEN)));

        int status = ScanProxyClient.sendAuditedToolsCall(wiring.sseProxy().port(),
                wiring.sseProxy().auditHeaders(Map.of()), "echo").statusCode();

        assertThat(status).isEqualTo(200);
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call") && carriesNoSentinel(request)
                        && ("Bearer " + SESSION_TOKEN).equals(request.headerValue("Authorization"))),
                any(RequestOptions.class));
    }

    @Test
    void aFuzzedOperationHeaderOnAScannerFramedRequestReachesTheServerAsSent() throws Exception {
        connectModern();

        sendManagedToolsCall("echo", framedAs("echo", Map.of(McpHeaders.NAME, "echo;payload")));

        assertUpstreamToolsCall("echo", "echo;payload");
    }

    @Test
    void aStaleOperationHeaderLeftByABodyPayloadIsFramedFromTheBodyWithoutAnEarlierRequest() throws Exception {
        connectModern();

        sendManagedToolsCall("echo'payload", framedAs("echo", Map.of(McpHeaders.NAME, "echo")));

        assertUpstreamToolsCall("echo'payload", "echo'payload");
    }

    @Test
    void anOperationHeaderOnARequestTheScannerDidNotFrameReachesTheServerAsTyped() throws Exception {
        connectModern();

        sendManagedToolsCall("echo", Map.of(McpHeaders.NAME, "edited"));

        assertUpstreamToolsCall("echo", "edited");
    }

    @Test
    void aProbeWhoseFuzzedProtocolVersionTheServerAnswersWith404KeepsTheLiveSession() throws Exception {
        serveOnlyTheNegotiatedProtocolVersion();
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP,
                new NoAuthStrategy()));

        java.net.http.HttpResponse<String> reply = sendManagedToolsCallReply(framedAs("echo",
                Map.of(McpHeaders.PROTOCOL_VERSION, FUZZED_PROTOCOL_VERSION)));

        assertThat(reply.statusCode()).isEqualTo(404);
        verify(http, times(1)).sendRequest(argThat(request -> isCallTo(request, "initialize")),
                any(RequestOptions.class));
    }

    @Test
    void aFuzzedOperationMethodHeaderOnAStreamableHttpSessionReachesTheServerWithoutReinitializing()
            throws Exception {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP,
                new NoAuthStrategy()));

        sendManagedToolsCall("echo", framedAs("echo", Map.of(McpHeaders.METHOD, "tools/call;payload")));

        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call")
                && "tools/call;payload".equals(headerValueIgnoringCase(request, McpHeaders.METHOD))),
                any(RequestOptions.class));
        verify(http, times(1)).sendRequest(argThat(request -> isCallTo(request, "initialize")),
                any(RequestOptions.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {McpHeaders.METHOD, McpHeaders.NAME, McpHeaders.PROTOCOL_VERSION})
    void aFuzzedOperationHeaderOnAModernHttpSessionReachesTheServerAsSent(String fuzzedHeader) throws Exception {
        connectModern();

        sendManagedToolsCallReply(framedAs("echo", Map.of(fuzzedHeader, "fuzzed;payload")));

        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call")
                && "fuzzed;payload".equals(headerValueIgnoringCase(request, fuzzedHeader))
                && carriesNoSentinel(request)), any(RequestOptions.class));
    }

    private void serveOnlyTheNegotiatedProtocolVersion() {
        ScriptedBurpHttp server = new ScriptedBurpHttp(request -> Optional.of(
                "tools/call".equals(FakeMcpServer.method(request)) && carriesUnknownProtocolVersion(request)
                        ? FakeMcpServer.exchange(request, 404, Map.of(), "Not Found")
                        : FakeMcpServer.respond(request)));
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> server.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
    }

    private static boolean carriesUnknownProtocolVersion(ProtocolHttpRequest request) {
        return request.headers().entrySet().stream()
                .anyMatch(header -> header.getKey().equalsIgnoreCase(McpHeaders.PROTOCOL_VERSION)
                        && !header.getValue().equals(FakeMcpServer.LEGACY_VERSION));
    }

    private void connectModern() {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP,
                new BearerTokenAuthStrategy(SESSION_TOKEN)));
    }

    private static Map<String, String> framedAs(String toolName, Map<String, String> headers) {
        Map<String, String> sent = new java.util.HashMap<>(headers);
        sent.put(ScannerSentinels.FRAMED_OPERATION_HEADER, FramedOperation.encode(Map.of(
                McpHeaders.METHOD, "tools/call", McpHeaders.NAME, toolName)));
        return sent;
    }

    private void assertUpstreamToolsCall(String bodyName, String headerName) {
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call")
                && request.bodyToString().contains("\"name\":\"" + bodyName + "\"")
                && headerName.equals(headerValueIgnoringCase(request, McpHeaders.NAME))
                && carriesNoSentinel(request)), any(RequestOptions.class));
    }

    private void sendManagedToolsCall(String toolName, Map<String, String> headers) throws Exception {
        assertThat(sendManagedToolsCallReply(toolName, headers).statusCode()).isEqualTo(200);
    }

    private java.net.http.HttpResponse<String> sendManagedToolsCallReply(Map<String, String> headers) throws Exception {
        return sendManagedToolsCallReply("echo", headers);
    }

    private java.net.http.HttpResponse<String> sendManagedToolsCallReply(String toolName, Map<String, String> headers)
            throws Exception {
        Map<String, String> sent = new java.util.HashMap<>(wiring.sseProxy().auditHeaders(Map.of()));
        sent.putAll(headers);
        return ScanProxyClient.sendAuditedToolsCall(wiring.sseProxy().port(), sent, toolName);
    }

    @ParameterizedTest
    @CsvSource({"false,Authorization,Bearer bob", "true,Cookie,user=bob"})
    void identityProbeReachesBurpWithOnlyItsOwnCredentialsAndWithoutScannerSentinels(boolean managedAudit,
            String credential, String identity) throws Exception {
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.STREAMABLE_HTTP,
                new BearerTokenAuthStrategy(SESSION_TOKEN)));

        int status = ScanProxyClient.sendAuditedToolsCall(wiring.sseProxy().port(),
                IdentityProbes.headers(wiring.sseProxy(), managedAudit, Map.of(credential, identity)), "echo")
                .statusCode();

        assertThat(status).isEqualTo(200);
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call") && carriesNoSentinel(request)
                        && identity.equals(headerValueIgnoringCase(request, credential))
                        && !("Bearer " + SESSION_TOKEN).equals(headerValueIgnoringCase(request, "Authorization"))),
                any(RequestOptions.class));
        verify(http, never()).sendRequest(argThat(request -> isCallTo(request, "tools/call")
                        && ("Bearer " + SESSION_TOKEN).equals(headerValueIgnoringCase(request, "Authorization"))),
                any(RequestOptions.class));
    }

    @Test
    void scanProxyDerivesParamHeadersFromTheForwardedArgumentsOfADiscoveredTool() throws Exception {
        serveToolDeclaringTenantHeader();
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP, new NoAuthStrategy()));

        int status = sendProxiedLookup(Map.of(ScannerSentinels.STRIP_AUTH_HEADER, "1", "Mcp-Param-Tenant", "stale"));

        assertThat(status).isEqualTo(200);
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call")
                        && "fuzzed".equals(headerValueIgnoringCase(request, "Mcp-Param-Tenant"))
                        && request.headers().stream().filter(header -> header.name().equalsIgnoreCase("Mcp-Param-Tenant"))
                                .count() == 1),
                any(RequestOptions.class));
    }

    @ParameterizedTest
    @MethodSource("primaryUserCredentials")
    void managedToolCallCarryingParamHeadersReachesTheServerWithThePrimaryUsersCredentials(AuthStrategy primaryUser)
            throws Exception {
        serveToolDeclaringTenantHeader();
        wiring.start(shutdown);
        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP, primaryUser));
        Map<String, String> launched = new java.util.HashMap<>(wiring.operationFramer().operation("tools/call",
                "{\"name\":\"lookup\",\"arguments\":{\"tenant\":\"fuzzed\"}}", 7).headers());
        launched.putAll(wiring.sseProxy().auditHeaders(Map.of()));

        int status = sendProxiedLookup(launched);

        assertThat(status).isEqualTo(200);
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call")
                        && "fuzzed".equals(headerValueIgnoringCase(request, "Mcp-Param-Tenant"))
                        && ("Bearer " + SESSION_TOKEN).equals(headerValueIgnoringCase(request, "Authorization"))),
                any(RequestOptions.class));
    }

    static List<AuthStrategy> primaryUserCredentials() {
        return List.of(new BearerTokenAuthStrategy(SESSION_TOKEN), new SignedInOAuthUser());
    }

    private static final class SignedInOAuthUser implements AuthStrategy {
        @Override
        public Map<String, String> headers() {
            return Map.of("Authorization", "Bearer " + SESSION_TOKEN);
        }

        @Override
        public boolean supportsRefresh() {
            return true;
        }

        @Override
        public Optional<AccessToken> currentToken() {
            return Optional.of(new AccessToken(SESSION_TOKEN, Optional.empty()));
        }

        @Override
        public String toString() {
            return "OAuth";
        }
    }

    @Test
    void operationFramerTakesParamHeadersFromTheLatestDiscoveredCatalog() {
        serveToolDeclaringTenantHeader();
        wiring.start(shutdown);
        McpServerConfig config = new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP, new NoAuthStrategy());
        wiring.clientManager().connect(config);
        String lookup = "{\"name\":\"lookup\",\"arguments\":{\"tenant\":\"acme\"}}";
        assertThat(wiring.operationFramer().operation("tools/call", lookup, 1).headers())
                .containsEntry("Mcp-Param-Tenant", "acme");

        wiring.clientManager().disconnect();
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
        wiring.clientManager().connect(config);

        assertThat(wiring.operationFramer().operation("tools/call", lookup, 1).headers())
                .doesNotContainKey("Mcp-Param-Tenant");
    }

    @Test
    void operationFramerAddsParamHeadersWhileTheRestOfTheCatalogIsStillBeingDiscovered() {
        List<Map<String, String>> framedDuringDiscovery = new java.util.ArrayList<>();
        serveToolDeclaringTenantHeader(request -> {
            if ("resources/list".equals(FakeMcpServer.method(request))) {
                framedDuringDiscovery.add(framedLookup());
            }
        });
        wiring.start(shutdown);

        wiring.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP, new NoAuthStrategy()));

        assertThat(framedDuringDiscovery).isNotEmpty()
                .allSatisfy(headers -> assertThat(headers).containsEntry("Mcp-Param-Tenant", "acme"));
    }

    @Test
    void disconnectForgetsTheDiscoveredParamHeaders() {
        serveToolDeclaringTenantHeader();
        wiring.start(shutdown);
        McpServerConfig config = new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP, new NoAuthStrategy());
        wiring.clientManager().connect(config);
        wiring.clientManager().disconnect();
        List<Map<String, String>> framedBeforeNewCatalog = new java.util.ArrayList<>();
        ScriptedBurpHttp server = new ScriptedBurpHttp(request -> {
            if ("tools/list".equals(FakeMcpServer.method(request))) {
                framedBeforeNewCatalog.add(framedLookup());
            }
            return Optional.of(FakeMcpServer.respond(request));
        });
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> server.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));

        wiring.clientManager().connect(config);

        assertThat(framedBeforeNewCatalog).isNotEmpty()
                .allSatisfy(headers -> assertThat(headers).doesNotContainKey("Mcp-Param-Tenant"));
    }

    private Map<String, String> framedLookup() {
        return wiring.operationFramer().operation("tools/call",
                "{\"name\":\"lookup\",\"arguments\":{\"tenant\":\"acme\"}}", 1).headers();
    }

    private void serveToolDeclaringTenantHeader() {
        serveToolDeclaringTenantHeader(request -> {});
    }

    private void serveToolDeclaringTenantHeader(java.util.function.Consumer<ProtocolHttpRequest> observer) {
        ScriptedBurpHttp server = new ScriptedBurpHttp(request -> {
            observer.accept(request);
            return Optional.of("tools/list".equals(FakeMcpServer.method(request))
                    ? FakeMcpServer.exchange(request, 200, Map.of("Content-Type", List.of("application/json")),
                            "{\"jsonrpc\":\"2.0\",\"id\":" + idOf(request) + ",\"result\":{\"tools\":[{"
                                    + "\"name\":\"lookup\",\"inputSchema\":{\"type\":\"object\",\"properties\":"
                                    + "{\"tenant\":{\"type\":\"string\",\"x-mcp-header\":\"Tenant\"}}}}]}}")
                    : FakeMcpServer.respond(request));
        });
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> server.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
    }

    private static long idOf(ProtocolHttpRequest request) {
        try {
            return McpObjectMapper.INSTANCE.readTree(request.body()).path("id").asLong();
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    private int sendProxiedLookup(Map<String, String> headers) throws Exception {
        java.net.http.HttpRequest.Builder request = java.net.http.HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + wiring.sseProxy().port() + "/mcp"))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":7,"
                        + "\"method\":\"tools/call\",\"params\":{\"name\":\"lookup\",\"arguments\":{\"tenant\":\"fuzzed\"}}}"));
        headers.forEach(request::header);
        return java.net.http.HttpClient.newHttpClient()
                .send(request.build(), java.net.http.HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private List<RecordingRequestOptions> sentOptions() {
        ArgumentCaptor<RequestOptions> options = ArgumentCaptor.forClass(RequestOptions.class);
        verify(http, atLeastOnce()).sendRequest(any(HttpRequest.class), options.capture());
        return options.getAllValues().stream().map(RecordingRequestOptions::recorded).toList();
    }

    private static boolean carriesCall(HttpRequest request, String method) {
        return request.bodyToString().contains("\"" + method + "\"");
    }

    private static boolean isCallTo(HttpRequest request, String method) {
        return ENDPOINT.equals(request.url()) && request.bodyToString().contains("\"" + method + "\"");
    }

    private static String headerValueIgnoringCase(HttpRequest request, String name) {
        return request.headers().stream().filter(header -> header.name().equalsIgnoreCase(name))
                .map(header -> header.value()).findFirst().orElse(null);
    }

    private static boolean carriesNoSentinel(HttpRequest request) {
        return request.headers().stream()
                .noneMatch(header -> header.name().toLowerCase(Locale.ROOT).startsWith("x-mcp-scanner-"));
    }
}
