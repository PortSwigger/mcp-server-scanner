package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PrmWellKnownProbeTest {

    private static final URI MCP_RESOURCE = URI.create("https://mcp.example.com:8443/sse");
    private static final URI EXPECTED_PRM_URL =
            URI.create("https://mcp.example.com:8443/.well-known/oauth-protected-resource");

    private Http http;
    private PrmToAsResolver resolver;
    private PrmWellKnownProbe probe;

    @BeforeEach
    void setUp() {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        http = mock(Http.class);
        resolver = mock(PrmToAsResolver.class);
        probe = new PrmWellKnownProbe(http, resolver);
    }

    @Test
    void probeDelegatesToResolverWhenPrmReturns200() {
        stubResponse(200);
        DiscoveredMetadata expected = sampleDiscoveredMetadata();
        when(resolver.resolve(EXPECTED_PRM_URL, DiscoverySource.PRM_WELL_KNOWN, MCP_RESOURCE))
                .thenReturn(Optional.of(expected));

        Optional<DiscoveredMetadata> result = probe.probe(MCP_RESOURCE);

        assertThat(result).containsSame(expected);
        verify(resolver).resolve(eq(EXPECTED_PRM_URL), eq(DiscoverySource.PRM_WELL_KNOWN), eq(MCP_RESOURCE));

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendRequest(captor.capture(), any(RequestOptions.class));
        assertThat(captor.getValue().url()).isEqualTo(EXPECTED_PRM_URL.toString());
        assertThat(captor.getValue().method()).isEqualTo("GET");
    }

    @Test
    void probeReturnsEmptyOn404() {
        stubResponse(404);

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeReturnsEmptyOnNullResponse() {
        stubNullResponse();

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeReturnsEmptyWhenResolverReturnsEmpty() {
        stubResponse(200);
        when(resolver.resolve(EXPECTED_PRM_URL, DiscoverySource.PRM_WELL_KNOWN, MCP_RESOURCE))
                .thenReturn(Optional.empty());

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
    }

    @Test
    void gateDenialSendsNoRequest() {
        PrmWellKnownProbe gated = new PrmWellKnownProbe(http, resolver,
                (url, purpose) -> com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate.Decision.deny(
                        new com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate.Reason(
                                url, "10.0.0.1", java.util.List.of("private"), purpose, "denied")),
                null);

        assertThat(gated.probe(MCP_RESOURCE)).isEmpty();
        verifyNoInteractions(http);
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeEmitsWarnLogWhenResponseNull() {
        McpEventLog eventLog = new McpEventLog(null);
        PrmWellKnownProbe probeWithLog = new PrmWellKnownProbe(http, resolver, eventLog);
        stubNullResponse();

        probeWithLog.probe(MCP_RESOURCE);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("PRM well-known fetch failed"));
    }

    private void stubResponse(int status) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
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

    private static DiscoveredMetadata sampleDiscoveredMetadata() {
        Issuer issuer = new Issuer("https://example/issuer");
        AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
        return new DiscoveredMetadata(URI.create(issuer.getValue()), DiscoverySource.PRM_WELL_KNOWN, metadata);
    }
}
