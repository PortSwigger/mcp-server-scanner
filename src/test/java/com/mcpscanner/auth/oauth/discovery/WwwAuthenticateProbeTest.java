package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.oauth.OAuthUrlValidator;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.HostResolver;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WwwAuthenticateProbeTest {

    private static final URI MCP_RESOURCE = URI.create("https://mcp.example.com/sse");
    private static final URI PRM_URL = URI.create("https://example/.well-known/oauth-protected-resource");

    private Http http;
    private PrmToAsResolver resolver;
    private WwwAuthenticateProbe probe;

    @BeforeEach
    void setUp() {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        http = mock(Http.class);
        resolver = mock(PrmToAsResolver.class);
        probe = new WwwAuthenticateProbe(http, resolver, allowAllGate(), null);
    }

    @Test
    void aStreamedReplyBurpWithholdsMeansNoChallengeAndDoesNotThrow() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
    }

    @Test
    void aFailureThatIsNotAStreamedReplyStillPropagates() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Connection refused"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> probe.probe(MCP_RESOURCE))
                .hasMessage("Connection refused");
    }

    @Test
    void closesTheMcpSessionTheProbeOpened() {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.headerValue("Mcp-Session-Id")).thenReturn("probe-session");
        HttpRequestResponse exchange = responseWith(response);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(exchange);

        probe.probe(MCP_RESOURCE);

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http, org.mockito.Mockito.times(2)).sendRequest(sent.capture(), any(RequestOptions.class));
        HttpRequest close = sent.getAllValues().get(1);
        assertThat(close.method()).isEqualTo("DELETE");
        assertThat(close.headerValue("Mcp-Session-Id")).isEqualTo("probe-session");
    }

    @Test
    void sendsNoDeleteWhenTheServerIssuedNoSession() {
        stubResponse(401, "Bearer realm=\"x\"");

        probe.probe(MCP_RESOURCE);

        verify(http, org.mockito.Mockito.times(1)).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    @Test
    void retainsChallengeScopesWhenResourceMetadataUrlRequiresWellKnownFallback() {
        stubResponse(401, "Bearer scope=\"files:read\"");
        URI wellKnown = URI.create("https://mcp.example.com/.well-known/oauth-protected-resource");
        DiscoveredMetadata metadata = sampleDiscoveredMetadata().withScopes(List.of("admin"));
        when(resolver.resolve(wellKnown, DiscoverySource.PRM_WELL_KNOWN, MCP_RESOURCE))
                .thenReturn(Optional.of(metadata));

        assertThat(probe.probe(MCP_RESOURCE).orElseThrow().selectedScopes()).containsExactly("files:read");
    }

    @Test
    void retainsProtectedResourceScopesWhenChallengeHasNoScopeParameter() {
        stubResponse(401, "Bearer resource_metadata=\"" + PRM_URL + "\"");
        DiscoveredMetadata metadata = sampleDiscoveredMetadata().withScopes(List.of("files:read"));
        when(resolver.resolve(PRM_URL, DiscoverySource.WWW_AUTHENTICATE_HEADER, MCP_RESOURCE))
                .thenReturn(Optional.of(metadata));

        assertThat(probe.probe(MCP_RESOURCE).orElseThrow().selectedScopes()).containsExactly("files:read");
    }

    @Test
    void challengeScopesOverrideAuthorizationServerScopes() {
        stubResponse(401, "Bearer resource_metadata=\"" + PRM_URL + "\", scope=\"files:read tools:invoke\"");
        DiscoveredMetadata metadata = sampleDiscoveredMetadata();
        metadata.asMetadata().setScopes(new com.nimbusds.oauth2.sdk.Scope("admin"));
        when(resolver.resolve(PRM_URL, DiscoverySource.WWW_AUTHENTICATE_HEADER, MCP_RESOURCE))
                .thenReturn(Optional.of(metadata));

        DiscoveredMetadata result = probe.probe(MCP_RESOURCE).orElseThrow();

        assertThat(result.selectedScopes()).containsExactly("files:read", "tools:invoke");
    }

    @Test
    void probeDelegatesToResolverWhenResourceMetadataPresent() {
        stubResponse(401, "Bearer realm=\"x\", resource_metadata=\"" + PRM_URL + "\"");
        DiscoveredMetadata expected = sampleDiscoveredMetadata();
        when(resolver.resolve(PRM_URL, DiscoverySource.WWW_AUTHENTICATE_HEADER, MCP_RESOURCE))
                .thenReturn(Optional.of(expected));

        Optional<DiscoveredMetadata> result = probe.probe(MCP_RESOURCE);

        assertThat(result).contains(expected.withWwwAuthenticateChallenge(
                "Bearer realm=\"x\", resource_metadata=\"" + PRM_URL + "\""));
        verify(resolver).resolve(eq(PRM_URL), eq(DiscoverySource.WWW_AUTHENTICATE_HEADER), eq(MCP_RESOURCE));

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).sendRequest(captor.capture(), any(RequestOptions.class));
        assertThat(captor.getValue().url()).isEqualTo(MCP_RESOURCE.toString());
        assertThat(captor.getValue().method()).isEqualTo("POST");
        assertThat(captor.getValue().bodyToString()).contains("\"method\":\"initialize\"");
        assertThat(captor.getValue().headerValue("Content-Type")).isEqualTo("application/json");
        assertThat(captor.getValue().headerValue("Accept")).isEqualTo("application/json, text/event-stream");
    }

    @Test
    void probeCapturesTheRawWwwAuthenticateChallenge() {
        String challenge = "Bearer realm=\"x\", resource_metadata=\"" + PRM_URL + "\"";
        stubResponse(401, challenge);
        when(resolver.resolve(PRM_URL, DiscoverySource.WWW_AUTHENTICATE_HEADER, MCP_RESOURCE))
                .thenReturn(Optional.of(sampleDiscoveredMetadata()));

        assertThat(probe.probe(MCP_RESOURCE).orElseThrow().wwwAuthenticateChallenge()).isEqualTo(challenge);
    }

    @Test
    void probeReturnsEmptyWhenHeaderLacksResourceMetadata() {
        stubResponse(401, "Bearer realm=\"x\"");

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeReturnsEmptyWhenStatusUnexpectedAndNoHeader() {
        stubResponse(200, null);

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeReturnsEmptyWhenResponseNull() {
        stubNullResponse();

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeRefusesResourceMetadataPointingAtLinkLocalAddress() {
        WwwAuthenticateProbe denyingProbe = new WwwAuthenticateProbe(http, resolver, denyAllGate(), null);
        stubResponse(401, "Bearer resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"");

        assertThat(denyingProbe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeRefusesResourceMetadataPointingAtPrivateRange() {
        WwwAuthenticateProbe denyingProbe = new WwwAuthenticateProbe(http, resolver, denyAllGate(), null);
        stubResponse(401, "Bearer resource_metadata=\"http://10.0.0.1/.well-known/oauth-protected-resource\"");

        assertThat(denyingProbe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeRefusesResourceMetadataWithJavascriptScheme() {
        // Hard-block classification — denied by ANY gate, even alwaysAllow.
        stubResponse(401, "Bearer resource_metadata=\"javascript:alert(1)\"");

        assertThat(probe.probe(MCP_RESOURCE)).isEmpty();
        verify(resolver, never()).resolve(any(), any(), any());
    }

    @Test
    void probeEmitsWarnLogWhenResponseNull() {
        McpEventLog eventLog = new McpEventLog(null);
        WwwAuthenticateProbe probeWithLog = new WwwAuthenticateProbe(http, resolver, allowAllGate(), eventLog);
        stubNullResponse();

        probeWithLog.probe(MCP_RESOURCE);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("WWW-Authenticate challenge probe failed"));
    }

    private void stubResponse(int status, String wwwAuthenticate) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.headerValue("WWW-Authenticate")).thenReturn(wwwAuthenticate);
        HttpRequestResponse rr = responseWith(response);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(rr);
    }

    private void stubNullResponse() {
        HttpRequestResponse rr = responseWith(null);
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
        return new DiscoveredMetadata(URI.create(issuer.getValue()), DiscoverySource.WWW_AUTHENTICATE_HEADER, metadata);
    }

    private static SuspiciousDestinationGate allowAllGate() {
        return new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), stubResolver(),
                SuspiciousDestinationConfirmer.alwaysAllow(), null);
    }

    private static SuspiciousDestinationGate denyAllGate() {
        return new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(), stubResolver(),
                SuspiciousDestinationConfirmer.alwaysDeny(), null);
    }

    private static HostResolver stubResolver() {
        return host -> List.of();
    }
}
