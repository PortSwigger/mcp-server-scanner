package com.mcpscanner.auth.oauth;

import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.AuthenticatedMcpServer;
import com.mcpscanner.testutil.AuthenticatedMcpServer.McpCall;
import com.mcpscanner.testutil.AuthenticatedMcpServer.TokenCall;
import com.mcpscanner.testutil.ClosedPort;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class OAuthAuthCodeScannerSessionTest {
    private static final URI CLIENT_METADATA_DOCUMENT = URI.create("https://client.example/scanner-metadata.json");
    private static final Duration CALLBACK_TIMEOUT = Duration.ofSeconds(60);
    private static final int CALLBACK_PORT_ATTEMPTS = 5;
    private static final String CALLBACK_PORT_TAKEN = "Failed to start callback listener";

    record Registration(String name, RegistrationMode mode, String clientId, String clientSecret) {
        @Override
        public String toString() {
            return name;
        }

        String expectedClientId() {
            return switch (mode) {
                case CIMD -> CLIENT_METADATA_DOCUMENT.toString();
                case DCR -> "dcr-client";
                default -> clientId;
            };
        }

        OAuthClientHints hints(URI issuer, int callbackPort) {
            boolean dynamic = mode == RegistrationMode.CIMD || mode == RegistrationMode.DCR;
            URI document = mode == RegistrationMode.CIMD ? CLIENT_METADATA_DOCUMENT : null;
            return new OAuthClientHints(issuer, List.of(), clientId, clientSecret, dynamic, callbackPort,
                    CALLBACK_TIMEOUT, mode, document);
        }
    }

    private final AtomicReference<URI> authorizationRequest = new AtomicReference<>();
    private AuthenticatedMcpServer server;
    private McpScannerSession scannerSession;

    @BeforeEach
    void startServer() throws IOException {
        MontoyaTestFactory.install();
        server = AuthenticatedMcpServer.start();
        server.requireIssuedAccessToken();
        scannerSession = new McpScannerSession(HttpClient.newHttpClient(), new McpEventLog(null));
    }

    @AfterEach
    void stopServer() {
        scannerSession.disconnect();
        server.close();
    }

    static Stream<Registration> registrations() {
        return Stream.of(
                new Registration("client ID metadata document", RegistrationMode.CIMD, null, null),
                new Registration("dynamic client registration", RegistrationMode.DCR, null, null),
                new Registration("pre-registered public client", RegistrationMode.PRE_REGISTERED, "pre-registered", null),
                new Registration("pre-registered confidential client", RegistrationMode.PRE_REGISTERED, "pre-registered", "client-secret"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registrations")
    void authorizationCodeGrantWithPkceAuthenticatesTheScannerSession(Registration registration) throws IOException {
        OAuthSession oauth = authorize(registration);
        connectScanner(oauth);

        assertThat(catalog()).contains(AuthenticatedMcpServer.TOOL_NAME);

        assertThat(oauth.registrationMode()).isEqualTo(registration.mode());
        assertThat(oauth.clientId()).isEqualTo(registration.expectedClientId());
        assertThat(query(authorizationRequest.get()))
                .containsEntry("client_id", registration.expectedClientId())
                .containsEntry("code_challenge_method", "S256")
                .containsEntry("resource", server.endpoint())
                .containsKey("code_challenge");
        assertThat(server.tokenCalls()).singleElement().satisfies(call -> {
            assertThat(call.form()).containsEntry("grant_type", "authorization_code")
                    .containsEntry("resource", server.endpoint())
                    .containsKey("code_verifier");
            assertPresentsClient(call, registration);
        });
        assertThat(authenticatedCalls()).isNotEmpty()
                .allSatisfy(call -> assertThat(call.header("Authorization")).isEqualTo("Bearer access-1"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registrations")
    void revokedAccessTokenIsRefreshedOnChallengeAndTheRequestRetried(Registration registration) throws IOException {
        connectScanner(authorize(registration));
        server.revokeIssuedAccessTokens();

        assertThat(catalog()).contains(AuthenticatedMcpServer.TOOL_NAME);

        assertThat(lastCall().header("Authorization")).isEqualTo("Bearer access-2");
        assertThat(server.tokenCalls()).hasSize(2).last().satisfies(call -> {
            assertThat(call.form()).containsEntry("grant_type", "refresh_token")
                    .containsEntry("refresh_token", "refresh-1")
                    .containsEntry("resource", server.endpoint());
            assertPresentsClient(call, registration);
        });
    }

    @org.junit.jupiter.api.Test
    void expiredTokenIsRefreshedBeforeSendToWritesItIntoTheRequest() throws IOException {
        Registration registration = registrations().findFirst().orElseThrow();
        com.mcpscanner.testutil.MutableClock clock = new com.mcpscanner.testutil.MutableClock(java.time.Instant.now());
        OAuthSession oauth = authorize(registration);
        scannerSession.connect(new McpServerConfig(server.endpoint(), TransportType.MODERN_HTTP,
                new OAuthAuthCodeStrategy(URI.create(server.origin()), oauth.clientId(), oauth.sharedSession(),
                        clock, McpEventLog.noop())));
        clock.advance(Duration.ofHours(2));
        var sendTo = new com.mcpscanner.scan.SendToConnectionPolicy(() -> false,
                () -> com.mcpscanner.scan.ScanConnection.unbound(baseline -> Map.of()), scannerSession::scannerHeaders);

        Map<String, String> handoff = sendTo.get().headers(Map.of());

        assertThat(handoff).containsEntry("Authorization", "Bearer access-2");
        assertThat(server.tokenCalls()).last().satisfies(call ->
                assertThat(call.form()).containsEntry("grant_type", "refresh_token"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registrations")
    void deniedRefreshFailsTheRequestWithoutReusingTheRevokedToken(Registration registration) throws IOException {
        connectScanner(authorize(registration));
        server.revokeIssuedAccessTokens();
        server.denyTokenRequests();

        assertThatThrownBy(this::catalog).isInstanceOf(RuntimeException.class);

        assertThat(server.tokenCalls()).last().satisfies(call ->
                assertThat(call.form()).containsEntry("grant_type", "refresh_token"));
        assertThat(lastCall().status()).isEqualTo(401);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registrations")
    void deniedCodeExchangeFailsBeforeAnyCredentialReachesTheMcpServer(Registration registration) {
        server.denyTokenRequests();

        assertThatThrownBy(() -> authorize(registration)).isInstanceOf(OAuthException.class);

        assertThat(server.tokenCalls()).singleElement().satisfies(call ->
                assertThat(call.form()).containsEntry("grant_type", "authorization_code"));
        assertThat(server.mcpCalls()).allSatisfy(call -> assertThat(call.header("Authorization")).isNull());
    }

    private OAuthSession authorize(Registration registration) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                return authorizeOn(freePort(), registration);
            } catch (OAuthException portTakenMeanwhile) {
                if (attempt == CALLBACK_PORT_ATTEMPTS
                        || !String.valueOf(portTakenMeanwhile.getMessage()).startsWith(CALLBACK_PORT_TAKEN)) {
                    throw portTakenMeanwhile;
                }
            }
        }
    }

    private OAuthSession authorizeOn(int callbackPort, Registration registration) {
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                this::approveInBrowser, Clock.systemUTC(), allowLoopbackFixture(), McpEventLog.noop(), new ClientMetadataDocumentHttp(callbackPort));
        return flow.connect(URI.create(server.endpoint()), registration.hints(URI.create(server.origin()), callbackPort));
    }

    private void connectScanner(OAuthSession oauth) {
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(URI.create(server.origin()), oauth.clientId(),
                oauth.sharedSession(), Clock.systemUTC(), McpEventLog.noop());
        scannerSession.connect(new McpServerConfig(server.endpoint(), TransportType.MODERN_HTTP, strategy));
    }

    private void approveInBrowser(URI authorization) {
        authorizationRequest.set(authorization);
        Map<String, String> parameters = query(authorization);
        URI callback = URI.create(parameters.get("redirect_uri") + "?code=authorization-code&state="
                + URLEncoder.encode(parameters.get("state"), StandardCharsets.UTF_8));
        try {
            HttpClient.newHttpClient().send(java.net.http.HttpRequest.newBuilder(callback).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding());
        } catch (IOException | InterruptedException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static void assertPresentsClient(TokenCall call, Registration registration) {
        if (registration.clientSecret() == null) {
            assertThat(call.form()).containsEntry("client_id", registration.expectedClientId());
            assertThat(call.authorization()).isNull();
            return;
        }
        String basic = Base64.getEncoder().encodeToString((registration.clientId() + ":" + registration.clientSecret())
                .getBytes(StandardCharsets.UTF_8));
        assertThat(call.authorization()).isEqualTo("Basic " + basic);
    }

    private String catalog() {
        return scannerSession.catalog("tools/list", null).result().toString();
    }

    private List<McpCall> authenticatedCalls() {
        return server.mcpCalls().stream().filter(call -> call.status() != 401).toList();
    }

    private McpCall lastCall() {
        List<McpCall> calls = server.mcpCalls();
        return calls.get(calls.size() - 1);
    }

    private static SuspiciousDestinationGate allowLoopbackFixture() {
        return (url, purpose) -> SuspiciousDestinationGate.Decision.allow();
    }

    private static int freePort() throws IOException {
        return ClosedPort.onLoopback();
    }

    private static Map<String, String> query(URI uri) {
        Map<String, String> parameters = new HashMap<>();
        for (String pair : uri.getRawQuery().split("&")) {
            int separator = pair.indexOf('=');
            parameters.put(URLDecoder.decode(pair.substring(0, separator), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(separator + 1), StandardCharsets.UTF_8));
        }
        return parameters;
    }

    private static final class ClientMetadataDocumentHttp extends RecordingRealHttp {
        private final String document;

        private ClientMetadataDocumentHttp(int callbackPort) {
            this.document = "{\"client_id\":\"" + CLIENT_METADATA_DOCUMENT + "\",\"client_name\":\"Scanner\","
                    + "\"redirect_uris\":[\"http://127.0.0.1:" + callbackPort + "/callback\"]}";
        }

        @Override
        public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions options) {
            if (!request.url().equals(CLIENT_METADATA_DOCUMENT.toString())) {
                return super.sendRequest(request, options);
            }
            sentUrls.add(request.url());
            return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + document));
        }
    }
}
