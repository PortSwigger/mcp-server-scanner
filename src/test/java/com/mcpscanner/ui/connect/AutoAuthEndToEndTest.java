package com.mcpscanner.ui.connect;

import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.BrowserLauncher;
import com.mcpscanner.auth.oauth.CallbackListenerFactory;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.discovery.ChallengeStrategy;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.AuthenticatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import com.mcpscanner.ui.OAuthConnectSupport;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.core.oauth.AuthorizationApproval;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mcpscanner.identity.credentials.CredentialNeedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AutoAuthEndToEndTest {

    private static final Duration CALLBACK_TIMEOUT = Duration.ofSeconds(5);

    private final McpEventLog eventLog = new McpEventLog(null);
    private AuthenticatedMcpServer server;
    private McpClientManager clientManager;
    private ConnectCoordinator coordinator;

    @BeforeEach
    void startServer() throws IOException {
        MontoyaTestFactory.install();
        server = AuthenticatedMcpServer.start();
        clientManager = new McpClientManager(eventLog);
        coordinator = new ConnectCoordinator(realOAuthSupport(), clientManager, eventLog);
    }

    @AfterEach
    void stopServer() {
        clientManager.disconnect();
        server.close();
    }

    @Test
    void serverWithoutAuthIsReachedWithNoCredentials() {
        ConnectionAttemptResult outcome = connect();

        assertThat(outcome.resolvedAuth()).isInstanceOf(NoAuthStrategy.class);
        assertThat(outcome.autoResolution()).isEqualTo("Detect → None");
        assertThat(outcome.result().tools()).extracting("name").contains(AuthenticatedMcpServer.TOOL_NAME);
        assertThat(server.mcpCalls()).allSatisfy(call -> assertThat(call.header("Authorization")).isNull());
        assertThat(server.tokenCalls()).isEmpty();
    }

    @Test
    void oauthServerIsReachedThroughTheBrowserFlowWithDynamicRegistration() {
        server.requireIssuedAccessToken();

        ConnectionAttemptResult outcome = connect();

        assertThat(outcome.autoResolution()).isEqualTo("Detect → OAuth 2.1 (Authorization code, DCR)");
        assertThat(outcome.result().tools()).extracting("name").contains(AuthenticatedMcpServer.TOOL_NAME);
        assertThat(server.tokenCalls()).singleElement().satisfies(call ->
                assertThat(call.grantType()).isEqualTo("authorization_code"));
        assertThat(server.mcpCalls().get(server.mcpCalls().size() - 1).header("Authorization"))
                .isEqualTo("Bearer access-1");
        assertThat(eventLog.snapshot()).anyMatch(entry ->
                entry.message().contains("Auth: Detect → OAuth 2.1 (Authorization code, DCR)"));
    }

    @Test
    void challengeWithoutOAuthMetadataStopsWithAnActionableMessageBeforeAnyBrowserFlow() {
        server.requireIssuedAccessToken();
        server.withholdOAuthMetadata();

        assertThatThrownBy(this::connect).isInstanceOf(CredentialNeedException.class)
                .hasMessage("The server needs credentials and advertises no OAuth sign-in");

        assertThat(server.tokenCalls()).isEmpty();
        assertThat(clientManager.isConnected()).isFalse();
    }

    private ConnectionAttemptResult connect() {
        OAuthClientHints hints = new OAuthClientHints(null, List.of(), null, null, true, OAuthClientHints.DEFAULT_REDIRECT_PORT,
                CALLBACK_TIMEOUT, RegistrationMode.AUTO, null);
        return coordinator.connect(ConnectAttempt.withOauth(server.endpoint(), TransportType.MODERN_HTTP,
                "127.0.0.1", AuthTypeNames.AUTO, hints, URI.create(server.endpoint())),
                (phase, message) -> { }, () -> { });
    }

    private OAuthConnectSupport realOAuthSupport() {
        RecordingRealHttp http = new RecordingRealHttp();
        SuspiciousDestinationGate allowFixture = (url, purpose) -> SuspiciousDestinationGate.Decision.allow();
        OAuthMetadataDiscoverer discoverer = OAuthMetadataDiscoverer.defaultInstance(
                http, eventLog, allowFixture, () -> true);
        OAuthAuthorizationFlow flow = new OAuthAuthorizationFlow(CallbackListenerFactory.defaultFactory(),
                BrowserLauncher.validated(this::approveInBrowser, allowFixture), Clock.systemUTC(), allowFixture,
                eventLog, http);
        OAuthConnectSupport support = mock(OAuthConnectSupport.class);
        when(support.probeAuthRequirement(any(), any())).thenAnswer(call ->
                discoverer.requirementFor(URI.create(call.getArgument(0)), ChallengeStrategy.POST));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenAnswer(call -> {
            OAuthClientHints hints = call.getArgument(0);
            OAuthSession session = flow.connect(call.getArgument(1), hints, call.getArgument(3));
            return new OAuthAuthCodeStrategy(hints.issuer(), session.clientId(), session.sharedSession(),
                    Clock.systemUTC(), eventLog,
                    scopes -> AuthorizationApproval.REQUIRE_PROMPT, session.registrationMode());
        });
        return support;
    }

    private void approveInBrowser(URI authorization) {
        Map<String, String> parameters = new HashMap<>();
        Arrays.stream(authorization.getRawQuery().split("&")).forEach(pair -> {
            String[] keyAndValue = pair.split("=", 2);
            parameters.put(keyAndValue[0], java.net.URLDecoder.decode(keyAndValue[1], StandardCharsets.UTF_8));
        });
        URI callback = URI.create(parameters.get("redirect_uri") + "?code=authorization-code&state="
                + URLEncoder.encode(parameters.get("state"), StandardCharsets.UTF_8));
        try {
            HttpClient.newHttpClient().send(java.net.http.HttpRequest.newBuilder(callback).GET().build(),
                    java.net.http.HttpResponse.BodyHandlers.discarding());
        } catch (IOException | InterruptedException failure) {
            throw new IllegalStateException(failure);
        }
    }
}
