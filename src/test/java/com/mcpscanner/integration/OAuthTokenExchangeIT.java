package com.mcpscanner.integration;

import com.mcpscanner.auth.oauth.CallbackListenerFactory;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.auth.oauth.OAuthMetadataConsistencyListener;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end integration test that proves Nimbus's OAuth HTTP (metadata resolve, DCR,
 * token exchange, refresh) genuinely travels through Burp's {@code api.http()} — here a
 * real-sending {@link RecordingRealHttp} — against a live {@code mcp-test-server --auth oauth}.
 *
 * <p>Gate with {@code MCP_OAUTH_IT=1}. Mirrors {@link McpActiveDcrMisconfigurationCheckIT}
 * for the open-vs-strict DCR differential.
 */
@EnabledIfEnvironmentVariable(named = "MCP_OAUTH_IT", matches = "1")
class OAuthTokenExchangeIT {

    // The loopback test-server is trusted by construction, so allow it explicitly.
    private static final SuspiciousDestinationGate ALLOW_LOOPBACK =
            (url, purpose) -> SuspiciousDestinationGate.Decision.allow();

    @BeforeEach
    void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void dcrOpen_fullFlowThroughBurp_yieldsTokensAndRefreshes() throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer("--auth", "oauth")) {
            URI issuer = URI.create("http://" + McpCheckItSupport.HOST + ":" + server.port());
            URI resource = URI.create(McpCheckItSupport.mcpEndpoint(server.port()));

            RecordingRealHttp http = new RecordingRealHttp(McpCheckItSupport.realHttpClient());
            OAuthAuthorizationFlow flow = flowThrough(http);

            // No client_id + allowDcr=true → the flow must register via the open /register
            // endpoint (DCR), then complete the code+token dance, all through Burp's Http.
            OAuthClientHints hints = new OAuthClientHints(
                    issuer, List.of(), null, null, true, 0, Duration.ofSeconds(20));

            OAuthSession session = flow.connect(resource, hints);

            assertThat(session.clientId()).as("DCR should have registered a client").isNotBlank();
            assertThat(session.tokens().accessToken()).isNotNull();
            assertThat(session.tokens().refreshToken())
                    .as("server issues a refresh token").isNotNull();

            // Now prove the refresh path also rides Burp's Http end-to-end.
            OAuthTokens refreshed = flow.refresh(
                    issuer,
                    session.clientId(),
                    session.clientSecret(),
                    session.tokens().refreshToken(),
                    resource);

            // The refresh round-tripped through Burp and the server issued a fresh token.
            // (The JWT bytes can match the original when both are minted in the same second,
            // so assert validity rather than inequality.)
            assertThat(refreshed.accessToken()).isNotNull();
            assertThat(refreshed.accessToken().getValue()).isNotBlank();
        }
    }

    @Test
    void dcrStrict_unauthenticatedRegistrationRejected() throws Exception {
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-dcr-strict")) {
            URI issuer = URI.create("http://" + McpCheckItSupport.HOST + ":" + server.port());
            URI resource = URI.create(McpCheckItSupport.mcpEndpoint(server.port()));

            RecordingRealHttp http = new RecordingRealHttp(McpCheckItSupport.realHttpClient());
            OAuthAuthorizationFlow flow = flowThrough(http);

            OAuthClientHints hints = new OAuthClientHints(
                    issuer, List.of(), null, null, true, 0, Duration.ofSeconds(20));

            // Strict DCR requires a Bearer on /register; the flow's unauthenticated DCR POST
            // (routed through Burp) must be rejected — surfaced as an OAuth/DCR exception.
            assertThatThrownBy(() -> flow.connect(resource, hints))
                    .isInstanceOf(OAuthException.class);
        }
    }

    private OAuthAuthorizationFlow flowThrough(RecordingRealHttp http) {
        return new OAuthAuthorizationFlow(
                CallbackListenerFactory.defaultFactory(),
                OAuthTokenExchangeIT::driveAuthorizeRedirect,
                Clock.systemUTC(),
                ALLOW_LOOPBACK,
                new McpEventLog(null),
                OAuthMetadataConsistencyListener.noop(),
                http);
    }

    /**
     * Stand-in for the browser: GETs the authorization endpoint (the test-server's MCP-SDK
     * provider auto-approves without a consent screen) and follows its redirect back to our
     * loopback callback listener, delivering the authorization code.
     */
    private static void driveAuthorizeRedirect(URI authorizeUri) {
        new Thread(() -> {
            try {
                HttpClient client = HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .connectTimeout(Duration.ofSeconds(5))
                        .build();
                HttpResponse<Void> response = client.send(
                        HttpRequest.newBuilder(authorizeUri).GET()
                                .timeout(Duration.ofSeconds(10)).build(),
                        HttpResponse.BodyHandlers.discarding());
                String location = response.headers().firstValue("location").orElse(null);
                if (location != null) {
                    client.send(
                            HttpRequest.newBuilder(URI.create(location)).GET()
                                    .timeout(Duration.ofSeconds(10)).build(),
                            HttpResponse.BodyHandlers.discarding());
                }
            } catch (Exception ignored) {
                // If the redirect dance fails, the flow times out waiting for the callback
                // and the test fails with a clear OAuth timeout — no need to rethrow here.
            }
        }).start();
    }
}
