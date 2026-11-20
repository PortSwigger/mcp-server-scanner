package com.mcpscanner.auth.oauth.discovery;

import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.AuthenticatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ClientCertificateBurpHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class AuthRequirementProbeTest {

    private AuthenticatedMcpServer server;
    private AuthRequirementProbe probe;

    @BeforeEach
    void startServer() throws IOException, GeneralSecurityException {
        MontoyaTestFactory.install();
        server = AuthenticatedMcpServer.start();
        ClientCertificateBurpHttp http = ClientCertificateBurpHttp.withoutClientCertificate();
        OAuthMetadataDiscoverer discoverer = OAuthMetadataDiscoverer.defaultInstance(http, McpEventLog.noop(),
                (url, purpose) -> SuspiciousDestinationGate.Decision.allow(), () -> true);
        probe = new AuthRequirementProbe(http, discoverer);
    }

    @AfterEach
    void stopServer() {
        server.close();
    }

    @Test
    void serverThatAnswersAnonymouslyNeedsNoAuth() {
        assertThat(probe.probe(URI.create(server.endpoint()), ChallengeStrategy.POST)).isInstanceOf(AuthRequirement.NotRequired.class);
    }

    @Test
    void bearerChallengeWithMetadataResolvesToOAuthWithDiscoveredIssuer() {
        server.requireIssuedAccessToken();

        AuthRequirement requirement = probe.probe(URI.create(server.endpoint()), ChallengeStrategy.POST);

        assertThat(requirement).isInstanceOfSatisfying(AuthRequirement.OAuth.class,
                oauth -> assertThat(oauth.metadata().issuer()).isEqualTo(URI.create(server.origin())));
    }

    @Test
    void bearerChallengeWithoutAnyMetadataRequiresCredentialsWithoutOAuth() {
        server.requireIssuedAccessToken();
        server.withholdOAuthMetadata();

        AuthRequirement requirement = probe.probe(URI.create(server.endpoint()), ChallengeStrategy.POST);

        assertThat(requirement).isInstanceOfSatisfying(AuthRequirement.CredentialsRequired.class,
                required -> {
                    assertThat(required.answer()).contains("advertises no OAuth sign-in");
                    assertThat(required.bearerExpected()).isTrue();
                });
    }

    @Test
    void nonBearerChallengeRequiresCredentialsWithoutAttemptingDiscovery() {
        server.requireUnobtainableCredentials();
        server.challengeWith("Basic realm=\"fixture\"");

        AuthRequirement requirement = probe.probe(URI.create(server.endpoint()), ChallengeStrategy.POST);

        assertThat(requirement).isInstanceOfSatisfying(AuthRequirement.CredentialsRequired.class,
                required -> {
                    assertThat(required.answer()).contains("Basic").contains("not OAuth");
                    assertThat(required.bearerExpected()).isFalse();
                });
    }

    @Test
    void unreachableServerIsUnsupportedWithAReason() {
        String endpoint = server.endpoint();
        server.close();

        AuthRequirement requirement = probe.probe(URI.create(endpoint), ChallengeStrategy.POST);

        assertThat(requirement).isInstanceOf(AuthRequirement.Unsupported.class);
    }

    @Test
    void sseEndpointGatingOnlyGetResolvesToOAuth() {
        server.requireIssuedAccessToken();

        AuthRequirement requirement = probe.probe(URI.create(server.sseEndpoint()), ChallengeStrategy.STREAM_GET);

        assertThat(requirement).isInstanceOfSatisfying(AuthRequirement.OAuth.class,
                oauth -> assertThat(oauth.metadata().issuer()).isEqualTo(URI.create(server.origin())));
    }

    @Test
    void autoTransportFallsBackToGetWhenPostIsNotAnswered() {
        server.requireIssuedAccessToken();

        AuthRequirement requirement = probe.probe(URI.create(server.sseEndpoint()), ChallengeStrategy.POST_THEN_STREAM_GET);

        assertThat(requirement).isInstanceOf(AuthRequirement.OAuth.class);
    }

    @Test
    void openSseEndpointWithoutAuthNeedsNoAuthAndTheProbeReturnsPromptly() {
        AuthRequirement requirement = org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
                java.time.Duration.ofSeconds(8),
                () -> probe.probe(URI.create(server.sseEndpoint()), ChallengeStrategy.STREAM_GET));

        assertThat(requirement).isInstanceOf(AuthRequirement.NotRequired.class);
    }

    @Test
    void postOnlyStrategyNeverFallsBackToGet() {
        server.requireIssuedAccessToken();

        AuthRequirement requirement = probe.probe(URI.create(server.sseEndpoint()), ChallengeStrategy.POST);

        assertThat(requirement).isInstanceOf(AuthRequirement.NotRequired.class);
    }
}
