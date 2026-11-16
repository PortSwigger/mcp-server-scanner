package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StreamedReplyProbeTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:18800/mcp");

    private final Http http = mock(Http.class);
    private AuthRequirementProbe probe;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        probe = new AuthRequirementProbe(http, mock(OAuthMetadataDiscoverer.class));
    }

    @Test
    void aReplyBurpRefusesToHandOverBecauseItStreamsMeansTheServerAnsweredWithoutCredentials() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));

        AuthRequirement requirement = probe.probe(ENDPOINT, ChallengeStrategy.POST_THEN_STREAM_GET);

        assertThat(requirement).isInstanceOf(AuthRequirement.NotRequired.class);
    }

    @Test
    void otherBurpFailuresStayUnanswered() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Connection refused"));

        AuthRequirement requirement = probe.probe(ENDPOINT, ChallengeStrategy.POST);

        assertThat(requirement).isInstanceOf(AuthRequirement.Unsupported.class);
    }
}
