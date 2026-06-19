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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PrmToAsResolverTest {

    private static final URI PRM_URL = URI.create("https://mcp.example.com/.well-known/oauth-protected-resource");
    private static final URI AS_ISSUER = URI.create("https://example/issuer");
    private static final URI AS_METADATA_URL = URI.create("https://example/issuer/.well-known/oauth-authorization-server");

    private Http http;
    private PrmToAsResolver resolver;
    private final Map<String, HttpRequestResponse> responsesByUrl = new HashMap<>();

    @BeforeEach
    void setUp() {
        com.mcpscanner.testutil.MontoyaTestFactory.install();
        http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    HttpRequestResponse stubbed = responsesByUrl.get(request.url());
                    return stubbed != null ? stubbed : responseWith(null);
                });
        resolver = new PrmToAsResolver(http, null, allowAllGate());
    }

    @Test
    void resolveReturnsDiscoveredMetadataWhenPrmAndAsBothValid() {
        stubResponse(PRM_URL, 200, "{\"authorization_servers\":[\"" + AS_ISSUER + "\"]}");
        stubResponse(AS_METADATA_URL, 200, validAsMetadata(AS_ISSUER.toString()));

        Optional<DiscoveredMetadata> result = resolver.resolve(PRM_URL, DiscoverySource.PRM_WELL_KNOWN);

        assertThat(result).isPresent();
        assertThat(result.get().issuer()).isEqualTo(AS_ISSUER);
        assertThat(result.get().source()).isEqualTo(DiscoverySource.PRM_WELL_KNOWN);
        assertThat(result.get().asMetadata().getIssuer().getValue()).isEqualTo(AS_ISSUER.toString());
    }

    @Test
    void resolveReturnsEmptyWhenPrmMissingAuthorizationServers() {
        stubResponse(PRM_URL, 200, "{\"resource\":\"https://mcp.example.com\"}");

        assertThat(resolver.resolve(PRM_URL, DiscoverySource.PRM_WELL_KNOWN)).isEmpty();
    }

    @Test
    void resolveReturnsEmptyWhenAsMetadataFetchReturns404() {
        stubResponse(PRM_URL, 200, "{\"authorization_servers\":[\"" + AS_ISSUER + "\"]}");
        stubResponse(AS_METADATA_URL, 404, "");

        assertThat(resolver.resolve(PRM_URL, DiscoverySource.PRM_WELL_KNOWN)).isEmpty();
    }

    @Test
    void resolveEmitsWarnLogWhenResponseNull() {
        McpEventLog eventLog = new McpEventLog(null);
        PrmToAsResolver resolverWithLog = new PrmToAsResolver(http, eventLog, allowAllGate());
        // PRM_URL not stubbed -> answer returns null response

        resolverWithLog.resolve(PRM_URL, DiscoverySource.PRM_WELL_KNOWN);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("PRM/AS document fetch failed"));
    }

    @Test
    void gateDeniesPrmUrlDoesNotIssueAnyHttpRequest() {
        SuspiciousDestinationGate denyingGate = (url, purpose) -> SuspiciousDestinationGate.Decision.deny(
                new SuspiciousDestinationGate.Reason(url, "10.0.0.1",
                        java.util.List.of(OAuthUrlValidator.CLASSIFICATION_PRIVATE),
                        purpose, "denied"));
        AtomicInteger sendInvocations = countingHttp();
        PrmToAsResolver gated = new PrmToAsResolver(http, null, denyingGate);

        Optional<DiscoveredMetadata> result = gated.resolve(PRM_URL, DiscoverySource.PRM_WELL_KNOWN);

        assertThat(result).isEmpty();
        assertThat(sendInvocations.get()).isZero();
    }

    @Test
    void gateDeniesAsMetadataUrlSkipsAsMetadataFetchButStillFetchesPrm() {
        stubResponse(PRM_URL, 200, "{\"authorization_servers\":[\"" + AS_ISSUER + "\"]}");
        SuspiciousDestinationGate selectiveGate = (url, purpose) -> {
            if (AS_METADATA_URL.equals(url)) {
                return SuspiciousDestinationGate.Decision.deny(
                        new SuspiciousDestinationGate.Reason(url, "10.0.0.1",
                                java.util.List.of(OAuthUrlValidator.CLASSIFICATION_PRIVATE),
                                purpose, "denied"));
            }
            return SuspiciousDestinationGate.Decision.allow();
        };
        PrmToAsResolver gated = new PrmToAsResolver(http, null, selectiveGate);

        Optional<DiscoveredMetadata> result = gated.resolve(PRM_URL, DiscoverySource.PRM_WELL_KNOWN);

        assertThat(result).isEmpty();
        verify(http).sendRequest(argThat(matchesUrl(PRM_URL)), any(RequestOptions.class));
        verify(http, never()).sendRequest(argThat(matchesUrl(AS_METADATA_URL)), any(RequestOptions.class));
    }

    private void stubResponse(URI uri, int status, String body) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        when(response.bodyToString()).thenReturn(body);
        responsesByUrl.put(uri.toString(), responseWith(response));
    }

    private AtomicInteger countingHttp() {
        AtomicInteger counter = new AtomicInteger();
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> {
                    counter.incrementAndGet();
                    HttpResponse response = mock(HttpResponse.class);
                    when(response.statusCode()).thenReturn((short) 200);
                    when(response.bodyToString()).thenReturn("");
                    return responseWith(response);
                });
        return counter;
    }

    private static HttpRequestResponse responseWith(HttpResponse response) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.response()).thenReturn(response);
        return rr;
    }

    private static ArgumentMatcher<HttpRequest> matchesUrl(URI uri) {
        return request -> request != null && uri.toString().equals(request.url());
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

    private static SuspiciousDestinationGate allowAllGate() {
        return new DefaultSuspiciousDestinationGate(
                new OAuthUrlValidator(),
                stubResolver(),
                SuspiciousDestinationConfirmer.alwaysAllow(),
                null);
    }

    private static HostResolver stubResolver() {
        return host -> java.util.List.of();
    }
}
