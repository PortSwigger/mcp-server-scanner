package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuthMetadataDiscoveryTrailTest {

    private static final String REALM_ONLY_CHALLENGE = "Bearer realm=\"mcp\"";
    private static final SuspiciousDestinationGate ALLOW_ALL =
            (url, purpose) -> SuspiciousDestinationGate.Decision.allow();
    private static final String ORIGIN = "https://mcp.example.com";

    private final Map<String, Reply> replies = new HashMap<>();
    private Http http;

    private record Reply(int status, String body, String challenge) {
    }

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> reply(invocation.getArgument(0)));
    }

    @Test
    void challengeReceivedByTheProbePostIsKeptWhenTheWellKnownPrmProbeProducesTheMetadata() throws Exception {
        replies.put("/mcp", new Reply(401, "", REALM_ONLY_CHALLENGE));
        replies.put("/.well-known/oauth-protected-resource", new Reply(200, prmDocument(), null));
        replies.put("/.well-known/oauth-authorization-server", new Reply(200, asDocument(), null));

        DiscoveredMetadata metadata = discover();

        assertThat(metadata.source()).isEqualTo(DiscoverySource.PRM_WELL_KNOWN);
        assertThat(metadata.wwwAuthenticateChallenge()).isEqualTo(REALM_ONLY_CHALLENGE);
    }

    @Test
    void challengeReceivedByTheProbePostIsKeptWhenTheAsWellKnownProbeProducesTheMetadata() throws Exception {
        replies.put("/mcp", new Reply(401, "", REALM_ONLY_CHALLENGE));
        replies.put("/.well-known/oauth-authorization-server", new Reply(200, asDocument(), null));

        DiscoveredMetadata metadata = discover();

        assertThat(metadata.source()).isEqualTo(DiscoverySource.AS_WELL_KNOWN);
        assertThat(metadata.wwwAuthenticateChallenge()).isEqualTo(REALM_ONLY_CHALLENGE);
    }

    @Test
    void failedWellKnownPrmFetchIsRecordedWhenTheAsWellKnownProbeProducesTheMetadata() throws Exception {
        replies.put("/mcp", new Reply(401, "", REALM_ONLY_CHALLENGE));
        replies.put("/.well-known/oauth-authorization-server", new Reply(200, asDocument(), null));

        DiscoveredMetadata metadata = discover();

        assertThat(metadata.fetchFailures().protectedResourceMetadata())
                .contains("status 404")
                .contains(ORIGIN + "/.well-known/oauth-protected-resource");
    }

    @Test
    void probePostWithoutAChallengeIsRecordedAsAFailedChallengeFetch() throws Exception {
        replies.put("/mcp", new Reply(200, "{}", null));
        replies.put("/.well-known/oauth-authorization-server", new Reply(200, asDocument(), null));

        DiscoveredMetadata metadata = discover();

        assertThat(metadata.wwwAuthenticateChallenge()).isNull();
        assertThat(metadata.fetchFailures().wwwAuthenticateChallenge())
                .contains("status 200")
                .contains("no WWW-Authenticate header");
    }

    @Test
    void successfulPrmFetchRecordsNoFailures() throws Exception {
        replies.put("/mcp", new Reply(401, "", REALM_ONLY_CHALLENGE));
        replies.put("/.well-known/oauth-protected-resource", new Reply(200, prmDocument(), null));
        replies.put("/.well-known/oauth-authorization-server", new Reply(200, asDocument(), null));

        DiscoveredMetadata metadata = discover();

        assertThat(metadata.fetchFailures()).isEqualTo(MetadataFetchFailures.none());
    }

    private DiscoveredMetadata discover() throws DiscoveryFailedException {
        return OAuthMetadataDiscoverer.defaultInstance(http, null, ALLOW_ALL, () -> true).discover(URI.create(ORIGIN + "/mcp"));
    }

    private String prmDocument() {
        return "{\"resource\":\"" + ORIGIN + "/mcp\",\"authorization_servers\":[\"" + ORIGIN + "\"]}";
    }

    private String asDocument() {
        return "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + ORIGIN + "/authorize\","
                + "\"token_endpoint\":\"" + ORIGIN + "/token\",\"response_types_supported\":[\"code\"]}";
    }

    private HttpRequestResponse reply(HttpRequest request) {
        Reply reply = replies.getOrDefault(URI.create(request.url()).getPath(), new Reply(404, "", null));
        String challengeHeader = reply.challenge() == null ? "" : "WWW-Authenticate: " + reply.challenge() + "\r\n";
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 " + reply.status() + " \r\n"
                + "Content-Type: application/json\r\n" + challengeHeader + "\r\n" + reply.body());
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.response()).thenReturn(response);
        return requestResponse;
    }
}
