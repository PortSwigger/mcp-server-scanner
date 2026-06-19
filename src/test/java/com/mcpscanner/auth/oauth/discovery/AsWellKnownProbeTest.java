package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AsWellKnownProbeTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final URI MCP_RESOURCE = URI.create("https://issuer.example.com/sse");
    private static final String EXPECTED_AS_URL =
            "https://issuer.example.com/.well-known/oauth-authorization-server";

    private Http http;
    private AsWellKnownProbe probe;

    @BeforeEach
    void setUp() {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        http = mock(Http.class);
        probe = new AsWellKnownProbe(http);
    }

    @Test
    void probeReturnsDiscoveredMetadataOnValidResponse() {
        stubResponse(200, validAsMetadata(ISSUER));

        Optional<DiscoveredMetadata> result = probe.probe(MCP_RESOURCE);

        assertThat(result).isPresent();
        assertThat(result.get().issuer()).isEqualTo(URI.create(ISSUER));
        assertThat(result.get().source()).isEqualTo(DiscoverySource.AS_WELL_KNOWN);
        assertThat(result.get().asMetadata().getIssuer().getValue()).isEqualTo(ISSUER);

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendRequest(captor.capture(), any(RequestOptions.class));
        assertThat(captor.getValue().url()).isEqualTo(EXPECTED_AS_URL);
        assertThat(captor.getValue().method()).isEqualTo("GET");
    }

    @Test
    void probeReturnsEmptyOn404() {
        stubResponse(404, "");

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
    }

    @Test
    void probeReturnsEmptyOnNullResponse() {
        stubNullResponse();

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
    }

    @Test
    void probeReturnsEmptyOnMalformedJson() {
        stubResponse(200, "{not valid json");

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
    }

    @Test
    void gateDenialSendsNoRequest() {
        AsWellKnownProbe gated = new AsWellKnownProbe(http,
                (url, purpose) -> com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate.Decision.deny(
                        new com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate.Reason(
                                url, "10.0.0.1", java.util.List.of("private"), purpose, "denied")),
                null);

        assertThat(gated.probe(MCP_RESOURCE)).isEmpty();
        verifyNoInteractions(http);
    }

    @Test
    void probeEmitsWarnLogWhenResponseNull() {
        McpEventLog eventLog = new McpEventLog(null);
        AsWellKnownProbe probeWithLog = new AsWellKnownProbe(http, eventLog);
        stubNullResponse();

        probeWithLog.probe(MCP_RESOURCE);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("AS well-known fetch failed"));
    }

    private void stubResponse(int status, String body) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.bodyToString()).thenReturn(body);
        stubHttpReturns(responseWith(response));
    }

    private void stubNullResponse() {
        stubHttpReturns(responseWith(null));
    }

    private void stubHttpReturns(HttpRequestResponse rr) {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(rr);
    }

    private static HttpRequestResponse responseWith(HttpResponse response) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        return rr;
    }

    private static String validAsMetadata(String issuer) {
        return "{"
                + "\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/token\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]"
                + "}";
    }
}
