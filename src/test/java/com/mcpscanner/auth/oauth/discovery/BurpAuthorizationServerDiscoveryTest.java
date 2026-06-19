package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BurpAuthorizationServerDiscoveryTest {

    private static final String PRM_BODY_POINTING_AT_AS = "{\n"
            + "  \"resource\": \"https://mcp.example.com/\",\n"
            + "  \"authorization_servers\": [\"https://auth.example.com\"]\n"
            + "}";

    private static final String AS_BODY = "{\n"
            + "  \"issuer\": \"https://auth.example.com\",\n"
            + "  \"authorization_endpoint\": \"https://auth.example.com/authorize\",\n"
            + "  \"token_endpoint\": \"https://auth.example.com/token\",\n"
            + "  \"registration_endpoint\": \"https://auth.example.com/register\"\n"
            + "}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpRequest mutatedRequest;
    @Mock private HttpService httpService;

    private BurpAuthorizationServerDiscovery discovery;

    @BeforeEach
    void setUp() {
        discovery = new BurpAuthorizationServerDiscovery();
        stubBaseRequest();
        stubMutationChain();
    }

    @Test
    void wwwAuthenticatePath_resolvesAsMetadata() {
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmOk = httpRequestResponse(200, PRM_BODY_POINTING_AT_AS);
        HttpRequestResponse asOk = httpRequestResponse(200, AS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asOk);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isPresent();
        AuthorizationServerMetadata metadata = result.metadata().get();
        assertThat(metadata.getRegistrationEndpointURI()).hasToString("https://auth.example.com/register");
        assertThat(result.probeResponses()).containsExactly(unauthChallenge, prmOk, asOk);
    }

    @Test
    void wellKnownFallback_whenNoWwwAuthenticate() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asOk = httpRequestResponse(200, AS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, asOk);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isPresent();
        assertThat(result.metadata().get().getRegistrationEndpointURI())
                .hasToString("https://auth.example.com/register");
        assertThat(result.probeResponses()).containsExactly(unauthChallenge, asOk);
    }

    @Test
    void allPathsFail_returnsEmpty() {
        HttpRequestResponse okBaseline = httpRequestResponse(200, "");
        HttpRequestResponse wellKnownNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(okBaseline, wellKnownNotFound);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isEmpty();
        assertThat(result.probeResponses()).containsExactly(okBaseline, wellKnownNotFound);
    }

    @Test
    void malformedPrm_fallsBackToWellKnown() {
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmGarbage = httpRequestResponse(200, "{ not json");
        HttpRequestResponse asOk = httpRequestResponse(200, AS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmGarbage, asOk);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isPresent();
        assertThat(result.probeResponses()).containsExactly(unauthChallenge, prmGarbage, asOk);
    }

    @Test
    void prmReturns404_fallsBackToWellKnown() {
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asOk = httpRequestResponse(200, AS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asOk);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isPresent();
        assertThat(result.probeResponses()).containsExactly(unauthChallenge, prmNotFound, asOk);
    }

    @Test
    void prmMissingAuthorizationServers_fallsBackToWellKnown() {
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmWithoutServers = httpRequestResponse(200,
                "{\"resource\":\"https://mcp.example.com/\"}");
        HttpRequestResponse asOk = httpRequestResponse(200, AS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmWithoutServers, asOk);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isPresent();
        assertThat(result.probeResponses()).containsExactly(unauthChallenge, prmWithoutServers, asOk);
    }

    @Test
    void unauthenticatedProbeReturnsNullResponse_fallsBackToWellKnown() {
        HttpRequestResponse nullResponse = mock(HttpRequestResponse.class);
        lenient().when(nullResponse.response()).thenReturn(null);
        HttpRequestResponse asOk = httpRequestResponse(200, AS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(nullResponse, asOk);

        BurpAuthorizationServerDiscovery.Result result = discovery.discover(http, baseRequestResponse);

        assertThat(result.metadata()).isPresent();
        assertThat(result.probeResponses()).containsExactly(nullResponse, asOk);
    }

    private void stubBaseRequest() {
        lenient().when(baseRequestResponse.request()).thenReturn(request);
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(true);
        lenient().when(httpService.host()).thenReturn("mcp.example.com");
        lenient().when(httpService.port()).thenReturn(443);
        lenient().when(request.headers()).thenReturn(List.of());
    }

    private void stubMutationChain() {
        lenient().when(request.withRemovedHeaders(anyList())).thenReturn(mutatedRequest);
        lenient().when(request.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
        lenient().when(mutatedRequest.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
        lenient().when(mutatedRequest.withRemovedHeaders(anyList())).thenReturn(mutatedRequest);
    }

    private HttpRequestResponse httpRequestResponse(int statusCode, String body) {
        return httpRequestResponseWithHeader(statusCode, null, null, body);
    }

    private HttpRequestResponse httpRequestResponseWithHeader(int statusCode, String headerName, String headerValue,
                                                              String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body == null ? "" : body);
        if (headerName != null) {
            lenient().when(response.headerValue(headerName)).thenReturn(headerValue);
        }
        return rr;
    }

    // --- Regression tests for the auth-bearing header strip + sentinel bug --------------------
    // discoverViaWwwAuthenticate previously used HeaderMutation.apply(baseline,
    // List.of("Authorization"), Map.of()), which left Cookie / contributed custom-auth headers
    // in place and skipped the ScannerSentinels.STRIP_AUTH_HEADER sentinel. When the local SSE
    // proxy was in the path, the proxy re-injected the session's stored auth — masking the
    // "Burp-side AS discovery via unauth" flow.
    //
    // These tests exercise the constructor that accepts a Supplier<AuthStrategy>, so the
    // unauthenticated probe strips every auth-bearing header (Authorization, Cookie, contributed
    // custom-auth headers) and sets the STRIP_AUTH_HEADER sentinel.

    @Test
    void unauthenticatedProbe_stripsAllAuthBearingHeaders_andSetsStripSentinel() {
        Supplier<AuthStrategy> authSupplier = () -> new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "secret"));
        BurpAuthorizationServerDiscovery authAwareDiscovery =
                new BurpAuthorizationServerDiscovery(McpEventLog.noop(), authSupplier);

        HttpHeader authHeader = httpHeader("Authorization", "Bearer original-token");
        HttpHeader cookieHeader = httpHeader("Cookie", "session=abc");
        HttpHeader customAuthHeader = httpHeader("X-Api-Key", "secret");
        HttpHeader contentTypeHeader = httpHeader("Content-Type", "application/json");
        when(request.headers()).thenReturn(List.of(authHeader, cookieHeader, customAuthHeader, contentTypeHeader));
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, asNotFound);

        authAwareDiscovery.discover(http, baseRequestResponse);

        ArgumentCaptor<List<HttpHeader>> removedCaptor = captureRemovedHeaders();
        TreeSet<String> removedNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        removedCaptor.getValue().forEach(h -> removedNames.add(h.name()));
        assertThat(removedNames)
                .as("unauthenticated probe must strip Authorization, Cookie, and contributed custom-auth headers")
                .contains("Authorization", "Cookie", "X-Api-Key");
        assertThat(removedNames)
                .as("unauthenticated probe must not strip Content-Type")
                .doesNotContain("Content-Type");

        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);
        verify(mutatedRequest, atLeastOnce()).withHeader(headerNameCaptor.capture(), headerValueCaptor.capture());
        TreeSet<String> overrideNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        overrideNames.addAll(headerNameCaptor.getAllValues());
        assertThat(overrideNames)
                .as("unauthenticated probe must set the strip-auth sentinel header")
                .contains(ScannerSentinels.STRIP_AUTH_HEADER);
    }

    @Test
    void unauthenticatedProbe_preservesMcpSessionId() {
        Supplier<AuthStrategy> authSupplier = NoAuthStrategy::new;
        BurpAuthorizationServerDiscovery authAwareDiscovery =
                new BurpAuthorizationServerDiscovery(McpEventLog.noop(), authSupplier);

        HttpHeader authHeader = httpHeader("Authorization", "Bearer original-token");
        HttpHeader sessionHeader = httpHeader("Mcp-Session-Id", "sess-123");
        when(request.headers()).thenReturn(List.of(authHeader, sessionHeader));
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, asNotFound);

        authAwareDiscovery.discover(http, baseRequestResponse);

        ArgumentCaptor<List<HttpHeader>> removedCaptor = captureRemovedHeaders();
        TreeSet<String> removedNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        removedCaptor.getValue().forEach(h -> removedNames.add(h.name()));
        assertThat(removedNames)
                .as("Authorization must still be stripped")
                .contains("Authorization");
        assertThat(removedNames)
                .as("Mcp-Session-Id must be preserved so the server replies on the existing session")
                .doesNotContain("Mcp-Session-Id");

        ArgumentCaptor<String> headerNameCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValueCaptor = ArgumentCaptor.forClass(String.class);
        verify(mutatedRequest, atLeastOnce()).withHeader(headerNameCaptor.capture(), headerValueCaptor.capture());
        TreeSet<String> overrideNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        overrideNames.addAll(headerNameCaptor.getAllValues());
        assertThat(overrideNames)
                .as("unauthenticated probe must set the strip-auth sentinel header")
                .contains(ScannerSentinels.STRIP_AUTH_HEADER);
    }

    @SuppressWarnings("unchecked")
    private ArgumentCaptor<List<HttpHeader>> captureRemovedHeaders() {
        ArgumentCaptor<List<HttpHeader>> captor = ArgumentCaptor.forClass(List.class);
        verify(request).withRemovedHeaders(captor.capture());
        return captor;
    }

    private HttpHeader httpHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }
}
