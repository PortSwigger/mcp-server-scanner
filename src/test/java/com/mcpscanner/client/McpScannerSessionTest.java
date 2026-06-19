package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.TokenRefresher;
import com.mcpscanner.mcp.McpProtocolVersions;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The Streamable-HTTP scanner handshake reads the initialize reply incrementally via the JDK
 * {@link HttpClient} so it can lift the JSON-RPC reply out of the first SSE event without waiting
 * for the stream to close. These tests stub {@code httpClient.send(..., ofInputStream())} and assert
 * the read path never blocks on a keep-alive {@code text/event-stream} (the streaming-initialize connect regression).
 */
@ExtendWith(MockitoExtension.class)
class McpScannerSessionTest {

    private static final URI ISSUER = URI.create("https://issuer.example.com");

    @Mock private Logging logging;
    @Mock private HttpClient httpClient;

    @BeforeAll
    static void installMontoyaFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void initialStateIsEmptyAndDisconnected() {
        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        assertThat(session.resolvedEndpoint()).isNull();
        assertThat(session.sseUrl()).isNull();
        assertThat(session.transportType()).isNull();
        assertThat(session.scannerHeaders()).isEmpty();
        assertThat(session.nextRequestId()).isEqualTo(1L);
    }

    @Test
    void streamableHttpConnectPerformsInitializeAndCapturesSessionId() throws Exception {
        stubHandshake(mockInitResponse("session-abc"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.resolvedEndpoint()).isEqualTo("http://localhost:8080/mcp");
        assertThat(session.transportType()).isEqualTo(TransportType.STREAMABLE_HTTP);
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-abc");
        assertThat(session.nextRequestId()).isEqualTo(2L);
    }

    @Test
    void initializeRequestShapeIsPreserved() throws Exception {
        stubHandshake(mockInitResponse("session-abc"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new BearerTokenAuthStrategy("secret-token")));

        HttpRequest initRequest = capturedRequests().stream()
                .filter(req -> "POST".equals(req.method()))
                .filter(req -> extractBody(req).contains("\"method\":\"initialize\""))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No initialize request was sent"));

        assertThat(initRequest.method()).isEqualTo("POST");
        assertThat(initRequest.uri()).isEqualTo(URI.create("http://localhost:8080/mcp"));
        assertThat(initRequest.headers().firstValue("Content-Type")).contains("application/json");
        assertThat(initRequest.headers().firstValue("Accept")).contains("application/json, text/event-stream");
        assertThat(initRequest.headers().firstValue("Authorization")).contains("Bearer secret-token");
    }

    @Test
    void connectAppliesTimeoutToOutgoingRequests() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(capturedRequests())
                .isNotEmpty()
                .allSatisfy(req -> assertThat(req.timeout()).contains(Duration.ofSeconds(10)));
    }

    @Test
    void scannerHeadersIncludeNegotiatedProtocolVersion() throws Exception {
        String initBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}";
        stubHandshake(mockInitResponseWithBody("session-x", initBody), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.scannerHeaders()).containsEntry("MCP-Protocol-Version", "2025-06-18");
    }

    @Test
    void scannerHeadersFallBackToScannerDefaultWhenServerOmitsProtocolVersion() throws Exception {
        String initBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        stubHandshake(mockInitResponseWithBody("session-x", initBody), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.scannerHeaders())
                .containsEntry("MCP-Protocol-Version", McpProtocolVersions.SCANNER);
    }

    @Test
    void negotiateProtocolVersion_parsesJsonResponse() throws Exception {
        String initBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}";
        stubHandshake(mockInitResponseWithBodyAndContentType("session-x", initBody, "application/json"),
                mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.scannerHeaders()).containsEntry("MCP-Protocol-Version", "2024-11-05");
    }

    @Test
    void negotiateProtocolVersion_parsesSseFramedResponse() throws Exception {
        String sseBody = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}\n\n";
        stubHandshake(mockInitResponseWithBodyAndContentType("session-x", sseBody, "text/event-stream"),
                mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.scannerHeaders()).containsEntry("MCP-Protocol-Version", "2025-06-18");
    }

    /**
     * Streaming-initialize connect regression. The initialize POST returns {@code text/event-stream} whose first SSE
     * event carries the JSON-RPC reply, then the server holds the stream open (never reaches EOF).
     * A read-to-end implementation ({@code readAllBytes()} / {@code bodyToString()}) blocks until the
     * request timeout and the connect rolls back even though the server answered correctly. The
     * incremental read takes the reply from the first event, so connect must return promptly.
     *
     * <p>{@code assertTimeoutPreemptively} runs the connect on a separate thread and aborts it at the
     * deadline, so a regression fails deterministically (timeout) instead of hanging the whole suite.
     */
    @Test
    void negotiateProtocolVersion_doesNotHangOnSseKeepAlive() throws Exception {
        String firstEvent = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}\n\n";
        KeepAliveBlockingInputStream sseStream = new KeepAliveBlockingInputStream(firstEvent);
        HttpResponse<InputStream> initResponse = mockResponseWithStreamAndContentType(
                "session-x", sseStream, "text/event-stream");
        stubHandshake(initResponse, mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        try {
            assertTimeoutPreemptively(Duration.ofSeconds(2),
                    () -> session.connect(streamableHttpConfig(new NoAuthStrategy())),
                    "connect must return promptly without waiting for SSE stream EOF");
            assertThat(session.scannerHeaders())
                    .containsEntry("Mcp-Session-Id", "session-x")
                    .containsEntry("MCP-Protocol-Version", "2025-06-18");
        } finally {
            sseStream.releaseAndClose();
        }
    }

    @Test
    void streamableHttpConnectIncludesBearerAuthInScannerHeaders() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new BearerTokenAuthStrategy("secret-token")));

        assertThat(session.scannerHeaders())
                .containsEntry("Authorization", "Bearer secret-token")
                .containsEntry("Mcp-Session-Id", "session-x");
    }

    @Test
    void connectWithCustomHeaderIncludesAuthInScannerHeaders() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(
                new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "secret-key"))));

        assertThat(session.scannerHeaders())
                .containsEntry("X-Api-Key", "secret-key")
                .containsEntry("Mcp-Session-Id", "session-x");
    }

    @Test
    void streamableHttpConnectSucceedsWhenInitializeReturnsNoSessionId() throws Exception {
        stubHandshake(mockInitResponse(null), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.resolvedEndpoint()).isEqualTo("http://localhost:8080/mcp");
        assertThat(session.transportType()).isEqualTo(TransportType.STREAMABLE_HTTP);
        assertThat(session.scannerHeaders()).doesNotContainKey("Mcp-Session-Id");
        assertThat(session.scannerHeaders())
                .containsEntry("MCP-Protocol-Version", McpProtocolVersions.SCANNER);
    }

    @Test
    void statelessServerStillNegotiatesProtocolVersion() throws Exception {
        String initBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}";
        stubHandshake(mockInitResponseWithBody(null, initBody), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.scannerHeaders())
                .containsEntry("MCP-Protocol-Version", "2025-06-18")
                .doesNotContainKey("Mcp-Session-Id");
    }

    @Test
    void notificationsInitializedCarriesSessionIdHeader() throws Exception {
        stubHandshake(mockInitResponse("session-abc"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        HttpRequest notification = capturedRequests().stream()
                .filter(req -> "POST".equals(req.method()))
                .filter(req -> extractBody(req).contains("notifications/initialized"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No notifications/initialized request was sent"));

        assertThat(notification.headers().firstValue("Mcp-Session-Id")).contains("session-abc");
    }

    @Test
    void connectInitializeBodyUsesFixedRequestIdOne() throws Exception {
        HttpResponse<InputStream> init1 = mockInitResponse("session-initial");
        HttpResponse<InputStream> notify1 = mockInitResponse(null);
        HttpResponse<InputStream> init2 = mockInitResponse("session-refreshed");
        HttpResponse<InputStream> notify2 = mockInitResponse(null);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init1, notify1, init2, notify2);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));
        session.nextRequestId();
        session.nextRequestId();
        session.refreshScannerSession();

        List<String> initializeBodies = capturedRequests().stream()
                .filter(req -> "POST".equals(req.method()))
                .map(McpScannerSessionTest::extractBody)
                .filter(body -> body.contains("\"method\":\"initialize\""))
                .toList();

        assertThat(initializeBodies).isNotEmpty();
        assertThat(initializeBodies).allSatisfy(body -> assertThat(body).contains("\"id\":1"));
    }

    @Test
    void streamableHttpConnectThrowsWhenInitializeRequestFails() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection reset"));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        assertThatThrownBy(() -> session.connect(streamableHttpConfig(new NoAuthStrategy())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to establish scanner session");
        assertThat(session.resolvedEndpoint()).isNull();
        assertThat(session.transportType()).isNull();
        assertThat(session.scannerHeaders()).isEmpty();
    }

    @Test
    void streamableHttpConnectThrowsWhenInitializeReturnsNonSuccessStatus() throws Exception {
        HttpResponse<InputStream> unauthorized = mockUnauthorizedResponse();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(unauthorized);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        assertThatThrownBy(() -> session.connect(streamableHttpConfig(new NoAuthStrategy())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to establish scanner session");
        assertThat(session.resolvedEndpoint()).isNull();
        assertThat(session.transportType()).isNull();
        assertThat(session.scannerHeaders()).isEmpty();
    }

    @Test
    void refreshScannerSessionReplacesSessionIdAndKeepsRequestIdMonotonic() throws Exception {
        HttpResponse<InputStream> init1 = mockInitResponse("session-initial");
        HttpResponse<InputStream> notify1 = mockInitResponse(null);
        HttpResponse<InputStream> init2 = mockInitResponse("session-refreshed");
        HttpResponse<InputStream> notify2 = mockInitResponse(null);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init1, notify1, init2, notify2);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));
        session.nextRequestId();
        session.nextRequestId();

        boolean refreshed = session.refreshScannerSession();

        assertThat(refreshed).isTrue();
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-refreshed");
        // The counter must stay monotonic across a 401-triggered refresh: resetting it would
        // re-issue JSON-RPC ids already in flight on the upstream session (duplicate-id bug).
        assertThat(session.nextRequestId()).isEqualTo(4L);
    }

    @Test
    void refreshScannerSessionDoesNotReuseRequestIdsAcrossRefresh() throws Exception {
        HttpResponse<InputStream> init1 = mockInitResponse("session-initial");
        HttpResponse<InputStream> notify1 = mockInitResponse(null);
        HttpResponse<InputStream> init2 = mockInitResponse("session-refreshed");
        HttpResponse<InputStream> notify2 = mockInitResponse(null);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init1, notify1, init2, notify2);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        long before = session.nextRequestId();
        session.refreshScannerSession();
        long after = session.nextRequestId();

        assertThat(after).isGreaterThan(before);
    }

    @Test
    void refreshScannerSessionReturnsFalseWhenNotConnected() {
        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        assertThat(session.refreshScannerSession()).isFalse();
        verifyNoInteractions(httpClient);
    }

    @Test
    void refreshScannerSessionFailureLogsErrorToEventLog() throws Exception {
        HttpResponse<InputStream> init = mockInitResponse("session-initial");
        HttpResponse<InputStream> notify = mockInitResponse(null);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init)
                .thenReturn(notify)
                .thenThrow(new IOException("refresh blew up"));

        McpEventLog eventLog = new McpEventLog(null);
        McpScannerSession session = new McpScannerSession(httpClient, logging, eventLog);
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        boolean refreshed = session.refreshScannerSession();

        assertThat(refreshed).isFalse();
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.ERROR
                        && entry.message().contains("Failed to establish scanner session"));
    }

    @Test
    void firstHandshakeLogsScannerSessionEstablishedInfoToEventLog() throws Exception {
        stubHandshake(mockInitResponse("session-abc"), mockInitResponse(null));

        McpEventLog eventLog = new McpEventLog(null);
        McpScannerSession session = new McpScannerSession(httpClient, logging, eventLog);
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("Scanner session established"));
    }

    @Test
    void refreshScannerSession_returnsFalseAndKeepsOldSessionWhenInitFails() throws Exception {
        HttpResponse<InputStream> init = mockInitResponse("session-initial");
        HttpResponse<InputStream> notify = mockInitResponse(null);
        HttpResponse<InputStream> unauthorized = mockUnauthorizedResponse();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init, notify, unauthorized);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-initial");

        boolean refreshed = session.refreshScannerSession();

        assertThat(refreshed).isFalse();
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-initial");
    }

    @Test
    void refreshScannerSession_keepsOldSessionWhenInitializedNotificationFails() throws Exception {
        HttpResponse<InputStream> init1 = mockInitResponse("session-initial");
        HttpResponse<InputStream> notify1 = mockInitResponse(null);
        HttpResponse<InputStream> init2 = mockInitResponse("session-new");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init1)
                .thenReturn(notify1)
                .thenReturn(init2)
                .thenThrow(new IOException("notifications/initialized failed"));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-initial");

        boolean refreshed = session.refreshScannerSession();

        assertThat(refreshed).isFalse();
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-initial");
    }

    // ------------------------------------------------------------------------------------------
    // refreshAuth
    // ------------------------------------------------------------------------------------------

    @Test
    void refreshAuthLogsInfoTrailOnSuccess() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));
        AtomicReference<String> token = new AtomicReference<>("OLD");
        AuthStrategy rotating = new AuthStrategy() {
            @Override public Map<String, String> headers() {
                return Map.of("Authorization", "Bearer " + token.get());
            }
            @Override public boolean supportsRefresh() { return true; }
            @Override public boolean refresh() { token.set("NEW"); return true; }
        };
        McpEventLog eventLog = new McpEventLog(null);
        McpScannerSession session = new McpScannerSession(httpClient, logging, eventLog);
        session.connect(streamableHttpConfig(rotating));

        assertThat(session.refreshAuth()).isTrue();
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("Auth refresh attempted"));
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("Auth refresh succeeded"));
    }

    @Test
    void refreshAuthLogsWarnWhenStrategyRefuses() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));
        AuthStrategy refusing = new AuthStrategy() {
            @Override public Map<String, String> headers() {
                return Map.of("Authorization", "Bearer X");
            }
            @Override public boolean supportsRefresh() { return true; }
            @Override public boolean refresh() { return false; }
        };
        McpEventLog eventLog = new McpEventLog(null);
        McpScannerSession session = new McpScannerSession(httpClient, logging, eventLog);
        session.connect(streamableHttpConfig(refusing));

        assertThat(session.refreshAuth()).isFalse();
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("Auth refresh failed"));
    }

    @Test
    void refreshAuthMergesRotatedBearerIntoScannerHeaders() throws Exception {
        AtomicReference<Instant> nowRef = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
        Clock movingClock = movingClock(nowRef);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> new OAuthTokens(
                new BearerAccessToken("NEW"),
                new RefreshToken("refresh-2"),
                nowRef.get().plusSeconds(600),
                "alice");
        OAuthAuthCodeStrategy oauth = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), "client-id", null, null,
                new OAuthTokens(new BearerAccessToken("OLD"),
                        new RefreshToken("refresh-1"),
                        nowRef.get().plusSeconds(600),
                        "alice"),
                refresher, movingClock, new McpEventLog(null));
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(oauth));

        assertThat(session.scannerHeaders()).containsEntry("Authorization", "Bearer OLD");

        nowRef.set(nowRef.get().plusSeconds(700));

        assertThat(session.refreshAuth()).isTrue();
        assertThat(session.scannerHeaders())
                .containsEntry("Authorization", "Bearer NEW")
                .containsEntry("Mcp-Session-Id", "session-x");
    }

    @Test
    void refreshAuthReturnsFalseForNonRefreshableStrategy() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new BearerTokenAuthStrategy("static")));

        assertThat(session.refreshAuth()).isFalse();
    }

    @Test
    void refreshAuthReturnsFalseWhenOAuthStrategyRefuses() throws Exception {
        AtomicReference<Instant> nowRef = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
        Clock movingClock = movingClock(nowRef);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            throw new OAuthException("refresh broke");
        };
        OAuthAuthCodeStrategy oauth = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), "client-id", null, null,
                new OAuthTokens(new BearerAccessToken("initial"),
                        new RefreshToken("refresh-1"),
                        nowRef.get().plusSeconds(600),
                        "alice"),
                refresher, movingClock, new McpEventLog(null));
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(oauth));

        nowRef.set(nowRef.get().plusSeconds(700));

        assertThat(session.refreshAuth()).isFalse();
        verify(logging, never()).logToError(contains("strategy declined"));
    }

    @Test
    void refreshAuthShortCircuitsWhenOAuthStrategyHasTerminallyFailed() throws Exception {
        Instant frozen = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(frozen, java.time.ZoneOffset.UTC);
        AtomicInteger refresherCallCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refresherCallCount.incrementAndGet();
            throw new OAuthException("invalid_grant");
        };
        OAuthAuthCodeStrategy oauth = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), "client-id", null, null,
                new OAuthTokens(new BearerAccessToken("initial"),
                        new RefreshToken("refresh-1"),
                        frozen.minusSeconds(60),
                        "alice"),
                refresher, clock, new McpEventLog(null));
        oauth.refresh();
        oauth.refresh();
        oauth.refresh();
        assertThat(oauth.isTerminallyFailed()).isTrue();
        int callsBeforeSessionRefresh = refresherCallCount.get();

        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(oauth));

        assertThat(session.refreshAuth()).isFalse();
        assertThat(refresherCallCount.get())
                .as("session refreshAuth must not call the refresher when circuit breaker is open")
                .isEqualTo(callsBeforeSessionRefresh);
    }

    @Test
    void refreshAuthIsSilentWhenStrategyDoesNotSupportRefresh() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new BearerTokenAuthStrategy("static")));

        assertThat(session.refreshAuth()).isFalse();
        verify(logging, never()).logToError(contains("Auth refresh"));
    }

    @Test
    void refreshAuthMergesUpdatedHeadersFromAnyRefreshableStrategy() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));
        AtomicReference<String> token = new AtomicReference<>("OLD");
        AuthStrategy rotating = new AuthStrategy() {
            @Override public Map<String, String> headers() {
                return Map.of("Authorization", "Bearer " + token.get());
            }
            @Override public boolean supportsRefresh() { return true; }
            @Override public boolean refresh() { token.set("NEW"); return true; }
        };

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(rotating));

        assertThat(session.scannerHeaders()).containsEntry("Authorization", "Bearer OLD");
        assertThat(session.refreshAuth()).isTrue();
        assertThat(session.scannerHeaders()).containsEntry("Authorization", "Bearer NEW");
    }

    // ------------------------------------------------------------------------------------------
    // Cleartext-auth and SSE-proxy guards.
    // ------------------------------------------------------------------------------------------

    @Test
    void connectRejectsPlainHttpWithAuthForNonLoopback() {
        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        assertThatThrownBy(() -> session.connect(new McpServerConfig(
                "http://example.com/mcp", TransportType.STREAMABLE_HTTP,
                new BearerTokenAuthStrategy("secret"))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https");
    }

    @Test
    void connectAllowsPlainHttpWithAuthForLoopback() throws Exception {
        stubHandshake(mockInitResponse("session-loop"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(new McpServerConfig(
                "http://127.0.0.1:8080/mcp", TransportType.STREAMABLE_HTTP,
                new BearerTokenAuthStrategy("secret")));

        assertThat(session.scannerHeaders()).containsEntry("Authorization", "Bearer secret");
    }

    @Test
    void sseConnectFailsFastWhenSseProxyUnavailable() {
        McpScannerSession session = new McpScannerSession(
                httpClient, logging, new McpEventLog(null), () -> false);

        assertThatThrownBy(() -> session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("SSE proxy");

        verifyNoInteractions(httpClient);
        assertThat(session.transportType()).isNull();
        assertThat(session.resolvedEndpoint()).isNull();
    }

    @Test
    void sseConnectProceedsWhenSseProxyAvailable() {
        HttpResponse<InputStream> sseResponse = mockSseDiscovery("event: endpoint\ndata: /custom-message\n\n");
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));

        McpScannerSession session = new McpScannerSession(
                httpClient, logging, new McpEventLog(null), () -> true);
        session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse"));

        assertThat(session.transportType()).isEqualTo(TransportType.SSE);
        assertThat(session.resolvedEndpoint()).isEqualTo("http://localhost:1234/custom-message");
    }

    @Test
    void streamableHttpConnectUnaffectedBySseProxyUnavailability() throws Exception {
        HttpResponse<InputStream> init = mockInitResponse("session-x");
        HttpResponse<InputStream> notify = mockInitResponse(null);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init, notify);

        McpScannerSession session = new McpScannerSession(
                httpClient, logging, new McpEventLog(null), () -> false);
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        assertThat(session.transportType()).isEqualTo(TransportType.STREAMABLE_HTTP);
        assertThat(session.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-x");
    }

    // ------------------------------------------------------------------------------------------
    // SSE message-endpoint resolution (stays on JDK HttpClient).
    // ------------------------------------------------------------------------------------------

    @Test
    void sseConnectResolvesMessageEndpointAndLeavesScannerHeadersEmpty() {
        HttpResponse<InputStream> sseResponse = mockSseDiscovery("event: endpoint\ndata: /custom-message\n\n");
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse"));

        assertThat(session.sseUrl()).isEqualTo("http://localhost:1234/sse");
        assertThat(session.resolvedEndpoint()).isEqualTo("http://localhost:1234/custom-message");
        assertThat(session.scannerHeaders()).isEmpty();
        assertThat(session.transportType()).isEqualTo(TransportType.SSE);
    }

    @Test
    void sseConnectFallsBackToMessageEndpointWhenDiscoveryFails() {
        CompletableFuture<HttpResponse<InputStream>> failing = new CompletableFuture<>();
        failing.completeExceptionally(new java.net.http.HttpTimeoutException("timed out"));
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failing);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse"));

        assertThat(session.resolvedEndpoint()).isEqualTo("http://localhost:1234/message");
    }

    @Test
    void refreshScannerSessionReturnsFalseForSseTransport() {
        HttpResponse<InputStream> sseResponse = mockSseDiscovery("event: endpoint\ndata: /message\n\n");
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse"));

        assertThat(session.refreshScannerSession()).isFalse();
    }

    // ------------------------------------------------------------------------------------------
    // Disconnect + session DELETE (JDK HttpClient).
    // ------------------------------------------------------------------------------------------

    @Test
    void disconnectClearsAllSessionStateAndClosesSseStream() throws Exception {
        String body = "event: endpoint\ndata: /message\n\n";
        CloseTrackingInputStream sseStream = new CloseTrackingInputStream(body);
        HttpResponse<InputStream> sseResponse = mock(HttpResponse.class);
        lenient().when(sseResponse.body()).thenReturn(sseStream);
        lenient().when(sseResponse.statusCode()).thenReturn(200);
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse"));
        session.disconnect();

        assertThat(session.resolvedEndpoint()).isNull();
        assertThat(session.sseUrl()).isNull();
        assertThat(session.transportType()).isNull();
        assertThat(session.scannerHeaders()).isEmpty();
        assertThat(session.nextRequestId()).isEqualTo(1L);
        assertThat(sseStream.closeCount()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void disconnectIsSafeWhenNotConnected() {
        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));

        session.disconnect();

        assertThat(session.resolvedEndpoint()).isNull();
        assertThat(session.scannerHeaders()).isEmpty();
    }

    @Test
    void disconnectIssuesDeleteWithSessionIdHeaderForStreamableHttp() throws Exception {
        HttpResponse<InputStream> init = mockInitResponse("abc-123");
        HttpResponse<InputStream> notify = mockInitResponse(null);
        HttpResponse<Void> delete = mockDeleteResponse(204);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init, notify, delete);

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new BearerTokenAuthStrategy("secret-token")));
        session.disconnect();

        HttpRequest deleteRequest = capturedRequests().stream()
                .filter(req -> "DELETE".equals(req.method()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No DELETE request was sent"));

        assertThat(deleteRequest.uri()).isEqualTo(URI.create("http://localhost:8080/mcp"));
        assertThat(deleteRequest.headers().firstValue("Mcp-Session-Id")).contains("abc-123");
        assertThat(deleteRequest.headers().firstValue("Authorization")).contains("Bearer secret-token");
    }

    @Test
    void disconnectDoesNotIssueDeleteWhenNoSessionId() throws Exception {
        stubHandshake(mockInitResponse(null), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));
        session.disconnect();

        assertThat(capturedRequests())
                .as("no DELETE should be sent when session id was never captured")
                .noneMatch(req -> "DELETE".equals(req.method()));
    }

    @Test
    void disconnectDoesNotIssueDeleteForSseTransport() throws Exception {
        HttpResponse<InputStream> sseResponse = mockSseDiscovery("event: endpoint\ndata: /message\n\n");
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(sseResponse));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(sseConfig(new NoAuthStrategy(), "http://localhost:1234/sse"));
        session.disconnect();

        verify(httpClient, never()).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void disconnectDoesNotThrowIfDeleteFails() throws Exception {
        HttpResponse<InputStream> init = mockInitResponse("abc-456");
        HttpResponse<InputStream> notify = mockInitResponse(null);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init)
                .thenReturn(notify)
                .thenThrow(new IOException("DELETE blew up"));

        McpEventLog eventLog = new McpEventLog(null);
        McpScannerSession session = new McpScannerSession(httpClient, logging, eventLog);
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        session.disconnect();

        assertThat(eventLog.snapshot())
                .as("DELETE failure should surface as a warn in the event log")
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("Session DELETE failed"));
    }

    @Test
    void disconnectLogsInfoOnSuccessfulDelete() throws Exception {
        HttpResponse<InputStream> init = mockInitResponse("abc-789");
        HttpResponse<InputStream> notify = mockInitResponse(null);
        HttpResponse<Void> delete = mockDeleteResponse(204);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(init, notify, delete);

        McpEventLog eventLog = new McpEventLog(null);
        McpScannerSession session = new McpScannerSession(httpClient, logging, eventLog);
        session.connect(streamableHttpConfig(new NoAuthStrategy()));
        session.disconnect();

        assertThat(eventLog.snapshot())
                .as("successful DELETE should log session-DELETE-sent info")
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("Session DELETE sent"));
    }

    @Test
    void sessionIdIsRedactedInLogs() throws Exception {
        String rawSessionId = "secret-session-abc123";
        stubHandshake(mockInitResponse(rawSessionId), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        ArgumentCaptor<String> outputCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> errorCaptor = ArgumentCaptor.forClass(String.class);
        verify(logging, atLeastOnce()).logToOutput(outputCaptor.capture());
        verify(logging, atLeast(0)).logToError(errorCaptor.capture());

        assertThat(outputCaptor.getAllValues())
                .as("session-id must never appear raw in info logs")
                .noneMatch(message -> message.contains(rawSessionId));
        assertThat(errorCaptor.getAllValues())
                .as("session-id must never appear raw in error logs")
                .noneMatch(message -> message.contains(rawSessionId));
    }

    @Test
    void scannerHeadersReturnsDefensiveCopy() throws Exception {
        stubHandshake(mockInitResponse("session-x"), mockInitResponse(null));

        McpScannerSession session = new McpScannerSession(httpClient, logging, new McpEventLog(null));
        session.connect(streamableHttpConfig(new NoAuthStrategy()));

        Map<String, String> first = session.scannerHeaders();
        Map<String, String> second = session.scannerHeaders();

        assertThat(second).isNotSameAs(first);
    }

    // ------------------------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private void stubHandshake(HttpResponse<InputStream> first, HttpResponse<InputStream> second) throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(first, second);
    }

    private List<HttpRequest> capturedRequests() throws Exception {
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, atLeastOnce()).send(captor.capture(), any(HttpResponse.BodyHandler.class));
        return captor.getAllValues();
    }

    private static Clock movingClock(AtomicReference<Instant> nowRef) {
        return new Clock() {
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            @Override public Instant instant() { return nowRef.get(); }
        };
    }

    private static McpServerConfig streamableHttpConfig(AuthStrategy auth) {
        return new McpServerConfig("http://localhost:8080/mcp", TransportType.STREAMABLE_HTTP, auth);
    }

    private static McpServerConfig sseConfig(AuthStrategy auth, String url) {
        return new McpServerConfig(url, TransportType.SSE, auth);
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> mockInitResponse(String sessionId) {
        return mockInitResponseWithBody(sessionId, "");
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> mockInitResponseWithBody(String sessionId, String body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("mcp-session-id"))
                .thenReturn(sessionId != null ? Optional.of(sessionId) : Optional.empty());
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(200);
        lenient().when(response.body())
                .thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        return response;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> mockInitResponseWithBodyAndContentType(
            String sessionId, String body, String contentType) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("mcp-session-id"))
                .thenReturn(sessionId != null ? Optional.of(sessionId) : Optional.empty());
        lenient().when(headers.firstValue("Content-Type")).thenReturn(Optional.of(contentType));
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(200);
        lenient().when(response.body())
                .thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        return response;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> mockResponseWithStreamAndContentType(
            String sessionId, InputStream body, String contentType) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("mcp-session-id"))
                .thenReturn(sessionId != null ? Optional.of(sessionId) : Optional.empty());
        lenient().when(headers.firstValue("Content-Type")).thenReturn(Optional.of(contentType));
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(200);
        lenient().when(response.body()).thenReturn(body);
        return response;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> mockUnauthorizedResponse() {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("mcp-session-id")).thenReturn(Optional.empty());
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(401);
        lenient().when(response.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        return response;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<Void> mockDeleteResponse(int statusCode) {
        HttpResponse<Void> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(statusCode);
        return response;
    }

    @SuppressWarnings("unchecked")
    private static HttpResponse<InputStream> mockSseDiscovery(String body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.body())
                .thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        lenient().when(response.statusCode()).thenReturn(200);
        return response;
    }

    private static String extractBody(HttpRequest request) {
        return request.bodyPublisher().map(publisher -> {
            BodyCollector collector = new BodyCollector();
            publisher.subscribe(collector);
            return collector.body();
        }).orElse("");
    }

    /**
     * Yields the bytes of {@code firstEvent} then blocks indefinitely on {@code read()},
     * simulating an SSE server that holds the connection open after the initialize
     * reply. Tests that complete must not depend on hitting EOF on this stream.
     */
    private static final class KeepAliveBlockingInputStream extends InputStream {
        private final ByteArrayInputStream firstEvent;
        private final CountDownLatch release = new CountDownLatch(1);

        KeepAliveBlockingInputStream(String firstEvent) {
            this.firstEvent = new ByteArrayInputStream(firstEvent.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public int read() throws IOException {
            if (firstEvent.available() > 0) {
                return firstEvent.read();
            }
            blockUntilReleased();
            return -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (firstEvent.available() > 0) {
                return firstEvent.read(b, off, len);
            }
            blockUntilReleased();
            return -1;
        }

        @Override
        public int available() {
            return firstEvent.available();
        }

        private void blockUntilReleased() throws IOException {
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        }

        @Override
        public void close() {
            release.countDown();
        }

        void releaseAndClose() {
            close();
        }
    }

    private static final class CloseTrackingInputStream extends InputStream {
        private final ByteArrayInputStream delegate;
        private int closeCount;

        CloseTrackingInputStream(String body) {
            this.delegate = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        }

        @Override public int read() throws IOException { return delegate.read(); }
        @Override public int read(byte[] b, int off, int len) throws IOException { return delegate.read(b, off, len); }
        @Override public int available() throws IOException { return delegate.available(); }
        @Override public void close() throws IOException { closeCount++; delegate.close(); }

        int closeCount() { return closeCount; }
    }

    private static final class BodyCollector implements java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer> {
        private final java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        @Override public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
        @Override public void onNext(java.nio.ByteBuffer item) {
            byte[] chunk = new byte[item.remaining()];
            item.get(chunk);
            buffer.writeBytes(chunk);
        }
        @Override public void onError(Throwable throwable) {}
        @Override public void onComplete() {}
        String body() { return buffer.toString(StandardCharsets.UTF_8); }
    }
}
