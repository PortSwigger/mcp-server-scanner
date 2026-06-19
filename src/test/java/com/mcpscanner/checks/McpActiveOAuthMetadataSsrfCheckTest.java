package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveOAuthMetadataSsrfCheckTest {

    private static final String VALID_PRM_HTTPS_BODY = "{\n"
            + "  \"resource\": \"https://mcp.example.com/\",\n"
            + "  \"authorization_servers\": [\"https://auth.example.com/\"],\n"
            + "  \"jwks_uri\": \"https://auth.example.com/jwks\"\n"
            + "}";

    private static final String VALID_AS_HTTPS_BODY = "{\n"
            + "  \"issuer\": \"https://auth.example.com\",\n"
            + "  \"authorization_endpoint\": \"https://auth.example.com/authorize\",\n"
            + "  \"token_endpoint\": \"https://auth.example.com/token\",\n"
            + "  \"jwks_uri\": \"https://auth.example.com/jwks\"\n"
            + "}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpRequest mutatedRequest;
    @Mock private HttpService httpService;
    @Mock private ScanCheckSettings settings;

    private McpActiveOAuthMetadataSsrfCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveOAuthMetadataSsrfCheck(settings);
    }

    @Test
    void descriptor_exposesOAuthMetadataSsrfMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("oauth-metadata-ssrf");
        assertThat(descriptor.displayName()).isEqualTo("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
        assertThat(descriptor.burpIssueName()).contains("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
    }

    @Test
    void checkName_returnsBurpIssueNameFromDescriptor() {
        assertThat(check.checkName()).isEqualTo("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("oauth-metadata-ssrf", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void nonMcpRequest_returnsEmpty() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\"hello\":\"world\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void allMetadataClean_returnsEmpty() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"https://auth.example.com/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmOk = httpRequestResponse(200, VALID_PRM_HTTPS_BODY);
        HttpRequestResponse asOk = httpRequestResponse(200, VALID_AS_HTTPS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asOk);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void engages_onResourcesReadBaseline() {
        stubMcpRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///x\"}}");
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name())
                .isEqualTo("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
    }

    @Test
    void engages_onPromptsGetBaseline() {
        stubMcpRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}");
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name())
                .isEqualTo("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
    }

    @Test
    void detailIdentifiesServerAsPublisherAndClientAsVictim() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = result.auditIssues().get(0).detail();
        // Direction: the MCP server publishes the unsafe URLs; the client is coerced.
        assertThat(detail).contains("coercing the client");
        // Hedge: exploitability depends on the consuming client.
        assertThat(detail).containsIgnoringCase("exploitability depends on the consuming client");
        assertThat(detail).contains("CVE-2025-6514");
    }

    @Test
    void wwwAuthenticatePointsAtImds_emitsCloudMetadataFinding() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("169.254.169.254");
        assertThat(issue.detail()).contains("cloud-metadata");
    }

    @Test
    void prmJwksUriIsLinkLocal_emitsLinkLocalFinding() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        String prmBody = "{\"resource\":\"https://mcp.example.com\","
                + "\"authorization_servers\":[\"https://auth.example.com\"],"
                + "\"jwks_uri\":\"http://169.254.0.1/jwks\"}";
        HttpRequestResponse prmOk = httpRequestResponse(200, prmBody);
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("jwks_uri");
        assertThat(result.auditIssues().get(0).detail()).contains("link-local");
    }

    @Test
    void prmAuthorizationServersHasPrivateIp_emitsPrivateFinding() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        String prmBody = "{\"resource\":\"https://mcp.example.com\","
                + "\"authorization_servers\":[\"http://10.0.0.1/\"]}";
        HttpRequestResponse prmOk = httpRequestResponse(200, prmBody);
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        String detail = result.auditIssues().get(0).detail();
        assertThat(detail).contains("authorization_servers[0]");
        assertThat(detail).contains("private");
    }

    @Test
    void asTokenEndpointIsHttp_emitsHttpDowngradeFinding() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        String asBody = "{\"issuer\":\"https://auth.example.com\","
                + "\"authorization_endpoint\":\"https://auth.example.com/authorize\","
                + "\"token_endpoint\":\"http://example.com/token\"}";
        HttpRequestResponse asOk = httpRequestResponse(200, asBody);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asOk);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        String detail = result.auditIssues().get(0).detail();
        assertThat(detail).contains("token_endpoint");
        assertThat(detail).contains("http-downgrade");
    }

    @Test
    void deRatesToInformationWhenMcpTargetHostIsLoopback() {
        stubMcpToolsCallRequest();
        when(httpService.host()).thenReturn("127.0.0.1");
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void deRatesToInformationWhenMcpTargetHostIsRfc1918() {
        stubMcpToolsCallRequest();
        when(httpService.host()).thenReturn("192.168.1.50");
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void staysMediumWhenMcpTargetHostIsPublic() {
        stubMcpToolsCallRequest();
        when(httpService.host()).thenReturn("mcp.example.com");
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void multipleBadUrlsAcrossDocuments_emitsOneCombinedIssue() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer resource_metadata=\"http://169.254.169.254/.well-known/oauth-protected-resource\"",
                "");
        String prmBody = "{\"resource\":\"https://mcp.example.com\","
                + "\"authorization_servers\":[\"http://10.0.0.1/\"]}";
        HttpRequestResponse prmOk = httpRequestResponse(200, prmBody);
        String asBody = "{\"issuer\":\"https://auth.example.com\","
                + "\"authorization_endpoint\":\"https://auth.example.com/authorize\","
                + "\"token_endpoint\":\"http://example.com/token\"}";
        HttpRequestResponse asOk = httpRequestResponse(200, asBody);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asOk);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        String detail = result.auditIssues().get(0).detail();
        assertThat(detail).contains("169.254.169.254");
        assertThat(detail).contains("10.0.0.1");
        assertThat(detail).contains("example.com/token");
        assertThat(detail).contains("cloud-metadata");
        assertThat(detail).contains("private");
        assertThat(detail).contains("http-downgrade");
    }

    @Test
    void prmEndpointReturns404_continuesWithRemainingProbes() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        String asBody = "{\"issuer\":\"https://auth.example.com\","
                + "\"authorization_endpoint\":\"https://auth.example.com/authorize\","
                + "\"token_endpoint\":\"http://example.com/token\"}";
        HttpRequestResponse asOk = httpRequestResponse(200, asBody);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asOk);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("token_endpoint");
    }

    @Test
    void prmEndpointReturnsInvalidJson_continuesWithRemainingProbes() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmGarbage = httpRequestResponse(200, "{ not json");
        String asBody = "{\"issuer\":\"https://auth.example.com\","
                + "\"authorization_endpoint\":\"https://auth.example.com/authorize\","
                + "\"token_endpoint\":\"http://example.com/token\"}";
        HttpRequestResponse asOk = httpRequestResponse(200, asBody);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmGarbage, asOk);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("token_endpoint");
    }

    @Test
    void doesNotFireWhenProbesReturnMcpToolErrorEnvelope() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        // Confirmation: oracle is URL classification of metadata documents — a tool-level
        // error envelope (result.isError: true) doesn't expose any unsafe URLs and must not
        // trigger this check.
        String toolErrorBody =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"invalid\"}],\"isError\":true}}";
        HttpRequestResponse toolError = httpRequestResponse(200, toolErrorBody);
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(toolError, prmNotFound, asNotFound);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void runs_once_per_host_on_per_request_dispatch() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmOk = httpRequestResponse(200, VALID_PRM_HTTPS_BODY);
        HttpRequestResponse asOk = httpRequestResponse(200, VALID_AS_HTTPS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asOk);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        reset(http);
        check.doCheck(baseRequestResponse, insertionPoint, http);

        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void runs_independently_for_distinct_hosts() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmOk = httpRequestResponse(200, VALID_PRM_HTTPS_BODY);
        HttpRequestResponse asOk = httpRequestResponse(200, VALID_AS_HTTPS_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmOk, asOk,
                unauthChallenge, prmOk, asOk);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        when(httpService.host()).thenReturn("other-host.example");
        check.doCheck(baseRequestResponse, insertionPoint, http);

        // Three probes (unauth challenge + PRM well-known + AS well-known) per invocation.
        verify(http, times(6)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void does_not_dedup_when_probe_sequence_had_http_layer_error() {
        stubMcpToolsCallRequest();
        stubMutationChain();
        HttpRequestResponse nullResponse = mock(HttpRequestResponse.class);
        lenient().when(nullResponse.response()).thenReturn(null);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(nullResponse);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.doCheck(baseRequestResponse, insertionPoint, http);

        verify(http, times(6)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void consolidateIssues_returnsKeepExistingForSameIssueName() {
        AuditIssue existing = issueWithName("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
        AuditIssue incoming = issueWithName("MCP OAuth Discovery Metadata Exposes Unsafe URLs");

        assertThat(check.consolidateIssues(existing, incoming)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
    }

    @Test
    void consolidateIssues_returnsKeepBothForDifferentNames() {
        AuditIssue existing = issueWithName("MCP OAuth Discovery Metadata Exposes Unsafe URLs");
        AuditIssue incoming = issueWithName("Something Else");

        assertThat(check.consolidateIssues(existing, incoming)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    private void stubMcpToolsCallRequest() {
        stubMcpRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\",\"arguments\":{}}}");
    }

    private void stubMcpRequestWithBody(String body) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(body);
        lenient().when(request.headers()).thenReturn(List.of());
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(true);
        lenient().when(httpService.host()).thenReturn("mcp.example.com");
        lenient().when(httpService.port()).thenReturn(443);
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

    private AuditIssue issueWithName(String name) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        return issue;
    }

    // --- Regression tests for the auth-bearing header strip + sentinel bug --------------------
    // The unauthenticated WWW-Authenticate probe used to call
    // HeaderMutation.apply(baseline, List.of("Authorization"), Map.of()), which left Cookie and
    // any active custom-auth header in place AND skipped the ScannerSentinels.STRIP_AUTH_HEADER
    // sentinel. When the local SSE proxy was in the path it would silently re-inject the
    // session's stored auth, masking every "WWW-Authenticate via no-auth" probe.
    //
    // These tests use the post-fix constructor that accepts a Supplier<AuthStrategy> — they will
    // fail to compile against current main, which is the intended TDD signal.

    @Test
    void unauthenticatedProbe_stripsAllAuthBearingHeaders_andSetsStripSentinel() {
        Supplier<AuthStrategy> authSupplier = () -> new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "secret"));
        McpActiveOAuthMetadataSsrfCheck authAwareCheck = new McpActiveOAuthMetadataSsrfCheck(
                settings, authSupplier, new com.mcpscanner.auth.oauth.OAuthUrlValidator(), null);

        stubMcpToolsCallRequest();
        HttpHeader authHeader = httpHeader("Authorization", "Bearer original-token");
        HttpHeader cookieHeader = httpHeader("Cookie", "session=abc");
        HttpHeader customAuthHeader = httpHeader("X-Api-Key", "secret");
        HttpHeader contentTypeHeader = httpHeader("Content-Type", "application/json");
        when(request.headers()).thenReturn(List.of(authHeader, cookieHeader, customAuthHeader, contentTypeHeader));
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        authAwareCheck.doCheck(baseRequestResponse, insertionPoint, http);

        // Capture the headers passed to withRemovedHeaders on the baseline (the unauth probe).
        ArgumentCaptor<List<HttpHeader>> removedCaptor = captureRemovedHeaders();
        TreeSet<String> removedNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        removedCaptor.getValue().forEach(h -> removedNames.add(h.name()));
        assertThat(removedNames)
                .as("unauthenticated probe must strip Authorization, Cookie, and contributed custom-auth headers")
                .contains("Authorization", "Cookie", "X-Api-Key");
        assertThat(removedNames)
                .as("unauthenticated probe must not strip Content-Type")
                .doesNotContain("Content-Type");

        // The strip-auth sentinel must be set so the SSE proxy doesn't re-inject session auth.
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
        McpActiveOAuthMetadataSsrfCheck authAwareCheck = new McpActiveOAuthMetadataSsrfCheck(
                settings, authSupplier, new com.mcpscanner.auth.oauth.OAuthUrlValidator(), null);

        stubMcpToolsCallRequest();
        HttpHeader authHeader = httpHeader("Authorization", "Bearer original-token");
        HttpHeader sessionHeader = httpHeader("Mcp-Session-Id", "sess-123");
        when(request.headers()).thenReturn(List.of(authHeader, sessionHeader));
        stubMutationChain();
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse prmNotFound = httpRequestResponse(404, "");
        HttpRequestResponse asNotFound = httpRequestResponse(404, "");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, prmNotFound, asNotFound);

        authAwareCheck.doCheck(baseRequestResponse, insertionPoint, http);

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
