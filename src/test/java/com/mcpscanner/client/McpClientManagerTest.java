package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.Audit;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.testutil.MontoyaTestFactory;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.mcp.client.McpClient;
import dev.langchain4j.mcp.client.McpPrompt;
import dev.langchain4j.mcp.client.McpPromptArgument;
import dev.langchain4j.mcp.client.McpResource;
import dev.langchain4j.mcp.client.McpResourceTemplate;
import dev.langchain4j.mcp.client.McpToolMetadataKeys;
import dev.langchain4j.mcp.client.McpCallContext;
import dev.langchain4j.mcp.client.transport.McpTransport;
import dev.langchain4j.mcp.protocol.McpClientMessage;
import dev.langchain4j.mcp.protocol.McpClientMethod;
import dev.langchain4j.mcp.protocol.McpInitializeRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the McpClientManager coordinator — the boundary that
 * wires together McpScannerSession and McpDiscoveryClient on connect/disconnect.
 * Behaviour of the individual modules is covered by McpScannerSessionTest and
 * McpDiscoveryClientTest.
 */
@ExtendWith(MockitoExtension.class)
class McpClientManagerTest {

    @Mock private Logging logging;
    @Mock private McpClient mcpClient;

    private McpClientManager manager;
    private McpEventLog eventLog;

    @BeforeAll
    static void installMontoyaFactory() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUp() {
        eventLog = new McpEventLog(null);
        // The streamable scanner-session handshake runs through the JDK HttpClient (send) and
        // hard-fails the connect if it can't capture an Mcp-Session-Id, so the shared manager
        // needs a mocked HttpClient that returns a valid initialize response on every send (so
        // reconnect tests work too) and an SSE endpoint event on sendAsync for SSE bring-up.
        manager = new McpClientManager(logging, eventLog, transport -> mcpClient, mockHttpClient());
    }

    @SuppressWarnings("unchecked")
    private static HttpClient mockHttpClient() {
        HttpResponse<InputStream> sseResponse = mockSseDiscoveryResponse("event: endpoint\ndata: /message\n\n");
        HttpResponse<InputStream> initResponse = jdkInitResponse("session-id");
        HttpClient httpClient = mock(HttpClient.class);
        try {
            lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(initResponse);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        lenient().when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));
        return httpClient;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> jdkInitResponse(String sessionId) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("mcp-session-id"))
                .thenReturn(sessionId != null ? Optional.of(sessionId) : Optional.empty());
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(200);
        lenient().when(response.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        return response;
    }

    @Test
    void isConnectedReturnsFalseInitially() {
        assertThat(manager.isConnected()).isFalse();
    }

    @Test
    void disconnectIsSafeWhenNotConnected() {
        manager.disconnect();

        assertThat(manager.isConnected()).isFalse();
        verifyNoInteractions(logging);
    }

    @Test
    void shutdownIsSafeWhenNotConnected() {
        manager.shutdown();

        assertThat(manager.isConnected()).isFalse();
        verifyNoInteractions(logging);
    }

    @Test
    void connectLogsConnectedInfoToEventLog() {
        when(mcpClient.listTools()).thenReturn(List.of());

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("Connected to MCP server")
                        && entry.message().contains("http://localhost:8080/mcp"));
    }

    @Test
    void connectLogsDiscoverySummaryToEventLog() {
        ToolSpecification toolSpec = ToolSpecification.builder()
                .name("tool-1").description("first").build();
        McpResource resource = new McpResource(
                "docs://a", "a", "an", "text/plain");
        McpResourceTemplate template = new McpResourceTemplate(
                "file:///{p}", "files", "f", "text/plain");
        McpPromptArgument arg = new McpPromptArgument("body", "the body", true);
        McpPrompt prompt = new McpPrompt("p", "p", List.of(arg));
        when(mcpClient.listTools()).thenReturn(List.of(toolSpec));
        when(mcpClient.listResources()).thenReturn(List.of(resource));
        when(mcpClient.listResourceTemplates()).thenReturn(List.of(template));
        when(mcpClient.listPrompts()).thenReturn(List.of(prompt));

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals(
                        "Discovered 1 tool, 1 resource, 1 resource template, 1 prompt"));
    }

    @Test
    void discoverySummaryPluralisesGracefullyForZeroAndMany() {
        ToolSpecification a = ToolSpecification.builder().name("a").build();
        ToolSpecification b = ToolSpecification.builder().name("b").build();
        when(mcpClient.listTools()).thenReturn(List.of(a, b));
        when(mcpClient.listResources()).thenReturn(List.of());

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals(
                        "Discovered 2 tools, 0 resources, 0 resource templates, 0 prompts"));
    }

    @Test
    void disconnectLogsDisconnectedInfoToEventLog() {
        when(mcpClient.listTools()).thenReturn(List.of());
        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        manager.disconnect();

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals("Disconnected from MCP server"));
    }

    @Test
    void notifyDisconnectListenerFailureLogsWarnToEventLog() {
        when(mcpClient.listTools()).thenReturn(List.of());
        Runnable throwing = mock(Runnable.class);
        doThrow(new RuntimeException("listener boom")).when(throwing).run();
        manager.addDisconnectListener(throwing);

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.disconnect();

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("Disconnect listener failed"));
    }

    @Test
    void connectReturnsConnectResultWithDiscoveredEntities() {
        ToolSpecification toolSpec = ToolSpecification.builder()
                .name("test-tool")
                .description("A test tool")
                .build();
        McpResource resource = new McpResource(
                "docs://readme", "Readme", "Server overview", "text/plain");
        McpResourceTemplate template = new McpResourceTemplate(
                "file:///{path}", "files", "files under root", "text/plain");
        McpPromptArgument arg = new McpPromptArgument("text", "the body", true);
        McpPrompt prompt = new McpPrompt("summarize", "summarise text", List.of(arg));
        when(mcpClient.listTools()).thenReturn(List.of(toolSpec));
        when(mcpClient.listResources()).thenReturn(List.of(resource));
        when(mcpClient.listResourceTemplates()).thenReturn(List.of(template));
        when(mcpClient.listPrompts()).thenReturn(List.of(prompt));

        ConnectResult result = manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        assertThat(result.tools()).hasSize(1);
        assertThat(result.tools().get(0).name()).isEqualTo("test-tool");
        assertThat(result.resources()).hasSize(1);
        assertThat(result.resourceTemplates()).hasSize(1);
        assertThat(result.prompts()).hasSize(1);
        assertThat(result.serverMetadata()).isEqualTo(ServerMetadata.empty());
        assertThat(manager.isConnected()).isTrue();
    }

    @Test
    void isConnectedTracksFullConnectDisconnectShutdownLifecycle() {
        when(mcpClient.listTools()).thenReturn(List.of());

        assertThat(manager.isConnected()).isFalse();

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        assertThat(manager.isConnected()).isTrue();

        manager.disconnect();
        assertThat(manager.isConnected()).isFalse();

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        assertThat(manager.isConnected()).isTrue();

        manager.shutdown();
        assertThat(manager.isConnected()).isFalse();
    }

    @Test
    void isConnectedDoesNotBlockOnTheConnectMonitorDuringAnInFlightConnect() throws Exception {
        // medium-E responsiveness: the EDT calls isConnected() on every renderState();
        // it must not acquire the connect monitor, otherwise a multi-second untrusted-server
        // bring-up freezes the UI. Hold the connect monitor open on a worker thread (the
        // transport factory blocks mid-connect) and assert isConnected() still returns promptly.
        java.util.concurrent.CountDownLatch insideConnect = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch releaseConnect = new java.util.concurrent.CountDownLatch(1);
        McpClientManager blocking = new McpClientManager(logging, new McpEventLog(null),
                transport -> mcpClient,
                mockHttpClient(),
                null,
                config -> {
                    insideConnect.countDown();
                    try {
                        releaseConnect.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return mock(dev.langchain4j.mcp.client.transport.McpTransport.class);
                });

        Thread connector = new Thread(() -> blocking.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null)));
        connector.start();
        try {
            assertThat(insideConnect.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

            CompletableFuture<Boolean> isConnectedCall =
                    CompletableFuture.supplyAsync(blocking::isConnected);
            assertThat(isConnectedCall.get(2, java.util.concurrent.TimeUnit.SECONDS)).isFalse();
        } finally {
            releaseConnect.countDown();
            connector.join(5_000);
        }
    }

    @Test
    void connectExposesScannerSession() {
        when(mcpClient.listTools()).thenReturn(List.of());

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        assertThat(manager.isConnected()).isTrue();
        assertThat(manager.scannerSession()).isNotNull();
        assertThat(manager.scannerSession().resolvedEndpoint()).isEqualTo("http://localhost:8080/mcp");
    }

    @Test
    void disconnectClosesDiscoveryClientAndClearsState() throws Exception {
        when(mcpClient.listTools()).thenReturn(List.of());

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.disconnect();

        verify(mcpClient).close();
        assertThat(manager.isConnected()).isFalse();
        assertThat(manager.scannerSession().resolvedEndpoint()).isNull();
    }

    @Test
    void disconnectSwallowsDiscoveryCloseFailure() throws Exception {
        when(mcpClient.listTools()).thenReturn(List.of());
        doThrow(new RuntimeException("close kaboom")).when(mcpClient).close();

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.disconnect();

        assertThat(manager.isConnected()).isFalse();
        verify(logging).logToError(org.mockito.ArgumentMatchers.contains("Error disconnecting"));
    }

    @Test
    void disconnectNotifiesRegisteredListener() {
        when(mcpClient.listTools()).thenReturn(List.of());
        Runnable listener = mock(Runnable.class);
        manager.addDisconnectListener(listener);

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.disconnect();

        verify(listener).run();
    }

    @Test
    void disconnectNotifiesAllListenersEvenIfOneThrows() {
        when(mcpClient.listTools()).thenReturn(List.of());
        Runnable throwing = mock(Runnable.class);
        doThrow(new RuntimeException("listener boom")).when(throwing).run();
        Runnable survivor = mock(Runnable.class);
        manager.addDisconnectListener(throwing);
        manager.addDisconnectListener(survivor);

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.disconnect();

        verify(throwing).run();
        verify(survivor).run();
    }

    @Test
    void removedListenerIsNoLongerNotified() {
        when(mcpClient.listTools()).thenReturn(List.of());
        Runnable listener = mock(Runnable.class);
        manager.addDisconnectListener(listener);
        manager.removeDisconnectListener(listener);

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.disconnect();

        verify(listener, never()).run();
    }

    @Test
    void reconnectNotifiesListenerForTheImplicitDisconnect() {
        when(mcpClient.listTools()).thenReturn(List.of());
        Runnable listener = mock(Runnable.class);

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.addDisconnectListener(listener);
        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        verify(listener).run();
    }

    @Test
    void shutdownNotifiesRegisteredDisconnectListeners() {
        when(mcpClient.listTools()).thenReturn(List.of());
        Runnable listener = mock(Runnable.class);
        manager.addDisconnectListener(listener);

        manager.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        manager.shutdown();

        verify(listener).run();
    }

    // ---------------------------------------------------------------------------------------
    // Audit lifecycle — bound to Connect/Disconnect so that captured langchain4j discovery
    // exchanges can be pushed into Burp's passive-scan engine for the duration of a session
    // (see T10). Audit is allocated lazily via an injectable supplier so unit tests can mock
    // it without depending on the real Burp Scanner runtime.
    // ---------------------------------------------------------------------------------------

    @Test
    void connectStartsAuditForCapturedDiscoveryExchanges() {
        Audit audit = mock(Audit.class);
        java.util.concurrent.atomic.AtomicInteger startCalls = new java.util.concurrent.atomic.AtomicInteger();
        McpClientManager.AuditFactory auditFactory = () -> {
            startCalls.incrementAndGet();
            return audit;
        };
        when(mcpClient.listTools()).thenReturn(List.of());

        McpClientManager m = newManagerWithAuditFactory(auditFactory);
        m.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));

        assertThat(startCalls.get()).isEqualTo(1);
    }

    @Test
    void disconnectDeletesAuditAndDropsTheReference() {
        Audit audit = mock(Audit.class);
        McpClientManager.AuditFactory auditFactory = () -> audit;
        when(mcpClient.listTools()).thenReturn(List.of());

        McpClientManager m = newManagerWithAuditFactory(auditFactory);
        m.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null));
        m.disconnect();

        verify(audit).delete();
    }

    @Test
    void connectFailureDoesNotLeakAuditReference() {
        // If anything between startAudit() and a successful connect throws, the Audit must
        // be deleted so we don't hold onto a Scanner task in Burp's state.
        Audit audit = mock(Audit.class);
        McpClientManager.AuditFactory auditFactory = () -> audit;

        McpClientManager exploding = new McpClientManager(logging, new McpEventLog(null),
                transport -> { throw new RuntimeException("boom"); },
                java.net.http.HttpClient.newHttpClient(),
                null,
                config -> mock(dev.langchain4j.mcp.client.transport.McpTransport.class),
                auditFactory);

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                exploding.connect(new McpServerConfig(
                        "https://example.com/mcp", TransportType.STREAMABLE_HTTP, null)))
                .isInstanceOf(RuntimeException.class);

        verify(audit).delete();
        assertThat(exploding.isConnected()).isFalse();
    }

    @Test
    void capturedDiscoveryExchangeIsForwardedToTheAudit() throws Exception {
        // End-to-end: the manager wires CapturingMcpTransport's publisher to a bridge that
        // pushes synthesised HttpRequestResponse pairs into the audit. When the test stub
        // transport completes a tools/list call, the audit must see exactly one pair.
        Audit audit = mock(Audit.class);
        McpClientManager.AuditFactory auditFactory = () -> audit;

        dev.langchain4j.agent.tool.ToolSpecification toolSpec =
                dev.langchain4j.agent.tool.ToolSpecification.builder().name("t").build();
        JsonNode toolsListEnvelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"t\"}]}}");

        McpClientManager m = newManagerCapturingToolsList(
                toolsListEnvelope, toolSpec, auditFactory);
        m.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP,
                new com.mcpscanner.auth.NoAuthStrategy()));

        verify(audit, org.mockito.Mockito.atLeastOnce())
                .addRequestResponse(any(burp.api.montoya.http.message.HttpRequestResponse.class));
    }

    private McpClientManager newManagerWithAuditFactory(McpClientManager.AuditFactory auditFactory) {
        return new McpClientManager(logging, new McpEventLog(null),
                transport -> mcpClient, mockHttpClient(), null, defaultTransportFactoryForTests(),
                auditFactory);
    }

    private static McpClientManager.McpTransportFactory defaultTransportFactoryForTests() {
        return config -> mock(dev.langchain4j.mcp.client.transport.McpTransport.class);
    }

    @SuppressWarnings("unchecked")
    private McpClientManager newManagerCapturingToolsList(JsonNode toolsListEnvelope,
                                                          dev.langchain4j.agent.tool.ToolSpecification toolSpec,
                                                          McpClientManager.AuditFactory auditFactory) throws Exception {
        dev.langchain4j.mcp.client.transport.McpTransport stubTransport =
                mock(dev.langchain4j.mcp.client.transport.McpTransport.class);
        lenient().when(stubTransport.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(toolsListEnvelope));

        java.util.concurrent.atomic.AtomicReference<CapturingMcpTransport> captorRef =
                new java.util.concurrent.atomic.AtomicReference<>();
        lenient().when(mcpClient.listTools()).thenAnswer(invocation -> {
            CapturingMcpTransport captor = captorRef.get();
            captor.executeOperationWithResponse(new McpCallContext(null,
                    new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();
            return List.of(toolSpec);
        });

        return new McpClientManager(logging, new McpEventLog(null),
                transport -> {
                    captorRef.set((CapturingMcpTransport) transport);
                    return mcpClient;
                },
                mockHttpClient(),
                null,
                config -> stubTransport,
                auditFactory);
    }

    @Test
    void connectFailureClearsStateAndDoesNotLeaveConnected() {
        McpClientManager exploding = new McpClientManager(logging, new McpEventLog(null),
                transport -> { throw new RuntimeException("boom"); },
                java.net.http.HttpClient.newHttpClient());

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                exploding.connect(new McpServerConfig(
                        "https://example.com/mcp", TransportType.STREAMABLE_HTTP, null)))
                .isInstanceOf(RuntimeException.class);

        assertThat(exploding.isConnected()).isFalse();
        assertThat(exploding.scannerSession().scannerHeaders()).isEmpty();
    }

    @Test
    void clientManagerConnectClearsStateWhenScannerSessionSetupFails() throws Exception {
        // The langchain4j discovery client is built, but the scanner-session handshake
        // fails: the initialize request returns a non-success status. The manager
        // must propagate the failure, close the discovery client, and leave
        // isConnected() false so the UI cannot pretend we're scan-ready.
        HttpResponse<InputStream> unauthorized = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("mcp-session-id")).thenReturn(Optional.empty());
        lenient().when(unauthorized.headers()).thenReturn(headers);
        lenient().when(unauthorized.statusCode()).thenReturn(401);
        lenient().when(unauthorized.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(unauthorized);

        McpClientManager scannerFailing = new McpClientManager(logging, new McpEventLog(null),
                transport -> mcpClient, httpClient);

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                scannerFailing.connect(new McpServerConfig(
                        "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, null)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to establish scanner session");
        assertThat(scannerFailing.isConnected()).isFalse();
        assertThat(scannerFailing.scannerSession().scannerHeaders()).isEmpty();
        verify(mcpClient).close();
    }


    @Test
    @SuppressWarnings("unchecked")
    void connectMergesIconsIntoToolDefinitionsOverStreamableHttp() throws Exception {
        // Icons now flow through the CapturingMcpTransport decorator instead of a raw
        // HTTP probe — this test asserts the Streamable-HTTP variant of that path.
        ToolSpecification toolSpec = ToolSpecification.builder()
                .name("logo_tool")
                .description("A tool with an icon")
                .build();
        JsonNode toolsListEnvelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":["
                        + "{\"name\":\"logo_tool\",\"icons\":["
                        + "{\"src\":\"file:///etc/passwd\",\"mimeType\":\"image/png\"}]}]}}");
        McpClientManager managerWithIcons = newManagerCapturingToolsList(toolsListEnvelope, toolSpec);

        ConnectResult result = managerWithIcons.connect(new McpServerConfig(
                "http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, new com.mcpscanner.auth.NoAuthStrategy()));

        assertThat(result.tools()).hasSize(1);
        assertThat(result.tools().get(0).icons()).hasSize(1);
        assertThat(result.tools().get(0).icons().get(0).src()).isEqualTo("file:///etc/passwd");
    }

    @Test
    @SuppressWarnings("unchecked")
    void connectOverSseDiscoversToolsWithIcons() throws Exception {
        // Regression guard: SSE servers reply 202-empty to a direct POST of tools/list,
        // so the previous raw-HttpClient probe silently dropped icons over SSE. The fix
        // routes icon discovery through the langchain4j transport — the
        // CapturingMcpTransport decorator stashes the tools/list envelope returned over
        // whichever wire (SSE or Streamable HTTP) langchain4j uses internally. This test
        // fails the moment any future change re-introduces a direct-HTTP escape hatch.
        ToolSpecification toolSpec = ToolSpecification.builder()
                .name("logo_tool")
                .description("a tool with an icon")
                .build();
        JsonNode toolsListEnvelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":["
                        + "{\"name\":\"logo_tool\",\"icons\":["
                        + "{\"src\":\"data:image/png;base64,iVBORw0K\",\"mimeType\":\"image/png\"}]}]}}");
        McpClientManager sseManager = newManagerCapturingToolsList(toolsListEnvelope, toolSpec);

        ConnectResult result = sseManager.connect(new McpServerConfig(
                "http://localhost:1234/sse", TransportType.SSE, new com.mcpscanner.auth.NoAuthStrategy()));

        assertThat(result.tools()).hasSize(1);
        assertThat(result.tools().get(0).icons()).hasSize(1);
        assertThat(result.tools().get(0).icons().get(0).src())
                .isEqualTo("data:image/png;base64,iVBORw0K");
    }

    /**
     * Builds a manager whose CapturingMcpTransport wraps a stub langchain4j transport
     * returning {@code toolsListEnvelope} on the {@link McpCallContext} overload of
     * {@code executeOperationWithResponse}. The supplied {@link ToolSpecification}
     * is what {@code mcpClient.listTools()} reports — and the stub drives the captor
     * inside that {@code listTools()} call, mirroring how
     * {@code DefaultMcpClient.obtainToolList} works at runtime. Both SSE and Streamable
     * HTTP exercise the same code path because the captor is transport-agnostic.
     */
    @SuppressWarnings("unchecked")
    private McpClientManager newManagerCapturingToolsList(JsonNode toolsListEnvelope,
                                                          ToolSpecification toolSpec) throws Exception {
        McpTransport stubTransport = mock(McpTransport.class);
        lenient().when(stubTransport.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(toolsListEnvelope));

        java.util.concurrent.atomic.AtomicReference<CapturingMcpTransport> captorRef =
                new java.util.concurrent.atomic.AtomicReference<>();
        lenient().when(mcpClient.listTools()).thenAnswer(invocation -> {
            CapturingMcpTransport captor = captorRef.get();
            captor.executeOperationWithResponse(new McpCallContext(null,
                    new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();
            return List.of(toolSpec);
        });

        // The scanner session opens its own connection on the JDK HttpClient: the Streamable-HTTP
        // handshake via send() and the SSE bring-up via sendAsync(). The shared mock stubs both so
        // we don't hit the network either way.
        return new McpClientManager(logging, new McpEventLog(null),
                transport -> {
                    captorRef.set((CapturingMcpTransport) transport);
                    return mcpClient;
                },
                mockHttpClient(),
                null,
                config -> stubTransport);
    }

    @Test
    @SuppressWarnings("unchecked")
    void connectOverSseDiscoversToolsWithAnnotations() {
        ToolSpecification toolSpec = ToolSpecification.builder()
                .name("reader")
                .description("read-only tool")
                .addMetadata(McpToolMetadataKeys.READ_ONLY_HINT, Boolean.TRUE)
                .addMetadata(McpToolMetadataKeys.DESTRUCTIVE_HINT, Boolean.FALSE)
                .addMetadata(McpToolMetadataKeys.IDEMPOTENT_HINT, Boolean.TRUE)
                .addMetadata(McpToolMetadataKeys.OPEN_WORLD_HINT, Boolean.FALSE)
                .addMetadata(McpToolMetadataKeys.TITLE_ANNOTATION, "Reader Tool")
                .build();
        when(mcpClient.listTools()).thenReturn(List.of(toolSpec));

        java.net.http.HttpClient httpClient = mock(java.net.http.HttpClient.class);
        java.net.http.HttpResponse<java.io.InputStream> sseResponse = mockSseDiscoveryResponse(
                "event: endpoint\ndata: /message\n\n");
        when(httpClient.sendAsync(any(java.net.http.HttpRequest.class), any(java.net.http.HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));

        McpClientManager sseManager = new McpClientManager(logging, new McpEventLog(null),
                transport -> mcpClient, httpClient);

        ConnectResult result = sseManager.connect(new McpServerConfig(
                "http://localhost:1234/sse", TransportType.SSE, new com.mcpscanner.auth.NoAuthStrategy()));

        assertThat(result.tools()).hasSize(1);
        ToolAnnotations annotations = result.tools().get(0).annotations();
        assertThat(annotations.readOnlyHint()).isTrue();
        assertThat(annotations.destructiveHint()).isFalse();
        assertThat(annotations.idempotentHint()).isTrue();
        assertThat(annotations.openWorldHint()).isFalse();
        assertThat(annotations.title()).isEqualTo("Reader Tool");
    }

    @Test
    void connectPopulatesServerMetadataWhenTransportCapturesInitializeResult() throws Exception {
        // Mirrors langchain4j's DefaultMcpClient driving McpTransport.initialize(...) during
        // setup: the CapturingMcpTransport decorator wraps the underlying transport and stores
        // the JSON-RPC envelope as a JsonNode. McpDiscoveryClient then parses ServerMetadata
        // out of that envelope. This same code path runs on both SSE and Streamable HTTP because
        // langchain4j already speaks each protocol's wire dance correctly inside its transport.
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                        + "\"protocolVersion\":\"2024-11-05\","
                        + "\"capabilities\":{\"resources\":{\"listChanged\":true}},"
                        + "\"instructions\":\"captured-instructions\","
                        + "\"serverInfo\":{\"name\":\"captured-server\",\"version\":\"7.7\"}}}");
        McpTransport underlyingTransport = mock(McpTransport.class);
        when(underlyingTransport.initialize(any(McpInitializeRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(underlyingTransport);
        captor.initialize(new McpInitializeRequest(1L)).get();

        ServerMetadata metadata = new McpDiscoveryClient(mcpClient, logging)
                .fetchServerMetadata(captor.initializeResult());

        assertThat(metadata.serverInfo())
                .containsEntry("name", "captured-server")
                .containsEntry("version", "7.7");
        assertThat(metadata.instructions()).isEqualTo("captured-instructions");
        assertThat(metadata.capabilities()).containsKey("resources");
    }

    @SuppressWarnings("unchecked")
    private static java.net.http.HttpResponse<java.io.InputStream> mockSseDiscoveryResponse(String body) {
        java.net.http.HttpResponse<java.io.InputStream> response = mock(java.net.http.HttpResponse.class);
        lenient().when(response.body())
                .thenReturn(new java.io.ByteArrayInputStream(body.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        lenient().when(response.statusCode()).thenReturn(200);
        return response;
    }
}
