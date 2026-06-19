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
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveUnauthenticatedToolDiscoveryCheckTest {

    private static final String ISSUE_NAME = "MCP Unauthenticated Tool Discovery";
    private static final String TOOLS_LIST_RESULT_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"exec\"}]}}";
    private static final String JSONRPC_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"bad\"}}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpRequest probeRequest;
    @Mock private HttpService httpService;
    @Mock private ScanCheckSettings settings;

    private McpActiveUnauthenticatedToolDiscoveryCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveUnauthenticatedToolDiscoveryCheck(settings, NoAuthStrategy::new);
    }

    @Test
    void descriptorExposesMergedMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("unauth-tool-discovery");
        assertThat(descriptor.displayName()).isEqualTo(ISSUE_NAME);
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        // T-deadcheck: PER_HOST-only checks with no scan-start hook were never invoked by Burp's
        // audit pipeline. PER_REQUEST drives them; internal HostDedup keeps the battery single-fire.
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
        // References are the deduplicated union of both predecessor checks.
        assertThat(descriptor.references()).containsExactlyInAnyOrder(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
                "https://cwe.mitre.org/data/definitions/306.html");
    }

    @Test
    void returnsEmptyWhenDisabled() {
        when(settings.isEnabled("unauth-tool-discovery", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void returnsEmptyForNonMcpRequest() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("GET");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void consolidatesIssuesByName() {
        AuditIssue existing = issueWithName(ISSUE_NAME);
        AuditIssue incoming = issueWithName(ISSUE_NAME);

        assertThat(check.consolidateIssues(existing, incoming))
                .isEqualTo(ConsolidationAction.KEEP_EXISTING);
        assertThat(check.consolidateIssues(existing, issueWithName("Other")))
                .isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    // ---- hadAuth branch: AUTH_NOT_ENFORCED ----

    @Test
    void hadAuth_firesAuthNotEnforcedWithConditionsWhenStrippedRequestLeaksTools() {
        stubMcpRequestWithHeaders("mcp.example.com", httpHeader("Authorization", "Bearer valid"));
        stubBodySwapAndProbeMutations();
        stubAllProbeResponses(200, TOOLS_LIST_RESULT_BODY);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssue(result);
        assertThat(issue.name()).isEqualTo(ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("Conditions that returned the tool list");
        assertThat(issue.detail()).contains("no Authorization header");
        assertThat(issue.detail()).containsIgnoringCase("execution");
        // Auth branch does not carry the reachability paragraph.
        assertThat(issue.detail()).doesNotContain("loopback or RFC1918");
    }

    @Test
    void hadAuth_onSseTransportDowngradesToTentativeAndAddsSessionCaveat() {
        // On SSE the local proxy preserves Mcp-Session-Id even under the strip
        // sentinel, so a session-binding server could answer the stripped probe
        // with an authorized session. Confidence drops to TENTATIVE and the
        // detail carries the SSE session caveat.
        check = new McpActiveUnauthenticatedToolDiscoveryCheck(
                settings, () -> new BearerTokenAuthStrategy("valid"), null, () -> TransportType.SSE);
        stubMcpRequestWithHeaders("mcp.example.com", httpHeader("Authorization", "Bearer valid"));
        stubBodySwapAndProbeMutations();
        stubAllProbeResponses(200, TOOLS_LIST_RESULT_BODY);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssue(result);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("Transport caveat (SSE)");
        assertThat(issue.detail()).contains("preserves the Mcp-Session-Id header");
    }

    @Test
    void hadAuth_onStreamableHttpTransportKeepsFirmConfidenceWithNoSessionCaveat() {
        check = new McpActiveUnauthenticatedToolDiscoveryCheck(
                settings, () -> new BearerTokenAuthStrategy("valid"), null,
                () -> TransportType.STREAMABLE_HTTP);
        stubMcpRequestWithHeaders("mcp.example.com", httpHeader("Authorization", "Bearer valid"));
        stubBodySwapAndProbeMutations();
        stubAllProbeResponses(200, TOOLS_LIST_RESULT_BODY);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssue(result);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).doesNotContain("Transport caveat (SSE)");
    }

    @Test
    void hadAuth_returnsEmptyWhenStrippedRequestStillRejected() {
        stubMcpRequestWithHeaders("mcp.example.com", httpHeader("Authorization", "Bearer valid"));
        stubBodySwapAndProbeMutations();
        stubAllProbeResponses(401, "{\"error\":\"unauthorized\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    // ---- no-auth branch: NO_AUTH ----

    @Test
    void noAuth_firesWithPublicHostFramingWhenUnauthenticatedProbeLeaksTools() {
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse probeResponse = httpRequestResponse(200, TOOLS_LIST_RESULT_BODY);
        when(http.sendRequest(probeRequest)).thenReturn(probeResponse);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssue(result);
        assertThat(issue.name()).isEqualTo(ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("publicly reachable");
        assertThat(issue.remediation()).contains("401").contains("127.0.0.1");
        // No-auth branch does not carry the conditions list from the auth branch.
        assertThat(issue.detail()).doesNotContain("Conditions that returned the tool list");
    }

    @Test
    void noAuth_firesWithLoopbackFramingForLoopbackHost() {
        stubMcpRequestWithHeaders("127.0.0.1");
        stubSingleProbeChain();
        HttpRequestResponse probeResponse = httpRequestResponse(200, TOOLS_LIST_RESULT_BODY);
        when(http.sendRequest(probeRequest)).thenReturn(probeResponse);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(singleIssue(result).detail()).contains("loopback or RFC1918");
    }

    @Test
    void noAuth_returnsEmptyWhenProbeReturns401() {
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse probeResponse = httpRequestResponse(401, "{\"error\":\"unauthorized\"}");
        when(http.sendRequest(probeRequest)).thenReturn(probeResponse);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void noAuth_returnsEmptyWhenProbeBodyIsJsonRpcError() {
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse probeResponse = httpRequestResponse(200, JSONRPC_ERROR_BODY);
        when(http.sendRequest(probeRequest)).thenReturn(probeResponse);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void noAuth_preservesMcpSessionIdOnTheProbe() {
        // The Mcp-Session-Id is a transport artifact, not a credential. Session-based servers
        // (FastMCP Streamable HTTP, SSE) reject session-less requests with a protocol error
        // (-32600 / HTTP 400 "Missing session ID") before any handler runs, so stripping it
        // would make the probe malformed and the check would never fire. The no-auth probe must
        // strip only credential headers (none are present on this branch) and keep the session
        // so the request is a genuine "valid transport session, no credentials" probe.
        HttpHeader sessionHeader = httpHeader("Mcp-Session-Id", "session-abc");
        stubMcpRequestWithHeaders("mcp.example.com", sessionHeader);
        wireMutationChainOn(request, new ArrayList<>(List.of(sessionHeader)));
        HttpRequestResponse probeResponse = httpRequestResponse(200, TOOLS_LIST_RESULT_BODY);
        ArgumentCaptor<HttpRequest> sentProbe = ArgumentCaptor.forClass(HttpRequest.class);
        when(http.sendRequest(sentProbe.capture())).thenReturn(probeResponse);

        check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(sentProbe.getValue().headers())
                .extracting(HttpHeader::name)
                .contains("Mcp-Session-Id");
    }

    @Test
    void noAuth_firesWhenSessionBoundServerLeaksToolsToCredentialStrippedProbe() {
        // Confirmed FastMCP --auth none false-negative: the server answers tools/list to any
        // request carrying a valid session id but no credentials. Preserving the session id while
        // stripping credentials produces a 200 + tools, so the check must fire.
        HttpHeader sessionHeader = httpHeader("Mcp-Session-Id", "session-abc");
        stubMcpRequestWithHeaders("mcp.example.com", sessionHeader);
        wireMutationChainOn(request, new ArrayList<>(List.of(sessionHeader)));
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            boolean carriesSession = sent.headers().stream()
                    .anyMatch(h -> h.name().equalsIgnoreCase("Mcp-Session-Id"));
            return carriesSession
                    ? httpRequestResponse(200, TOOLS_LIST_RESULT_BODY)
                    : httpRequestResponse(400, JSONRPC_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssue(result);
        assertThat(issue.name()).isEqualTo(ISSUE_NAME);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void dedupsRepeatedInsertionPointsAgainstSameHost() {
        // PER_REQUEST dispatch fires this check once per insertion point (~29 per scan). HostDedup
        // must run the probe battery once and cheaply skip the rest.
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse probeResponse = httpRequestResponse(200, TOOLS_LIST_RESULT_BODY);
        when(http.sendRequest(probeRequest)).thenReturn(probeResponse);

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isNotEmpty();
        assertThat(second.auditIssues()).isEmpty();
        verify(http).sendRequest(any(HttpRequest.class));
    }

    @Test
    void transientHttpLayerErrorReleasesClaimSoNextInsertionPointReprobes() {
        // A transient HTTP-layer failure (timeout / dropped stream) on the FIRST insertion point
        // returns no response. The check must release the host claim so a later insertion point on
        // the same host retries the probe — otherwise discovery is silently disabled for the scan.
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse transient_ = transientFailure();
        HttpRequestResponse working = httpRequestResponse(200, TOOLS_LIST_RESULT_BODY);
        when(http.sendRequest(probeRequest)).thenReturn(transient_, working);

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isNotEmpty();
    }

    @Test
    void cleanNegativeKeepsClaimSoNextInsertionPointSkips() {
        // A reachable server that answers cleanly (HTTP 401, no leak) must KEEP the claim so the
        // probe does not re-run on every one of the ~29 insertion points in a scan.
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse rejected = httpRequestResponse(401, "{\"error\":\"unauthorized\"}");
        when(http.sendRequest(probeRequest)).thenReturn(rejected);

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isEmpty();
        // No re-probe: the clean negative kept the claim, so only one probe was ever sent.
        verify(http).sendRequest(any(HttpRequest.class));
    }

    @Test
    void clearSessionStateAllowsReprobeAfterReconnect() {
        stubMcpRequestWithHeaders("mcp.example.com");
        stubSingleProbeChain();
        HttpRequestResponse probeResponse = httpRequestResponse(200, TOOLS_LIST_RESULT_BODY);
        when(http.sendRequest(probeRequest)).thenReturn(probeResponse);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.clearSessionState();
        AuditResult afterReconnect = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(afterReconnect.auditIssues()).isNotEmpty();
    }

    private AuditIssue singleIssue(AuditResult result) {
        assertThat(result.auditIssues()).hasSize(1);
        return result.auditIssues().get(0);
    }

    private void stubMcpRequestWithHeaders(String host, HttpHeader... headers) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString())
                .thenReturn("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}");
        lenient().when(request.headers()).thenReturn(List.of(headers));
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn(host);
        lenient().when(httpService.port()).thenReturn(8080);
    }

    private void stubBodySwapAndProbeMutations() {
        HttpRequest toolsListBaseline = mock(HttpRequest.class);
        HttpRequest mutatedRequest = mock(HttpRequest.class);
        HttpHeader baselineAuth = httpHeader("Authorization", "Bearer valid");
        when(request.withBody(anyString())).thenReturn(toolsListBaseline);
        lenient().when(toolsListBaseline.headers()).thenReturn(List.of(baselineAuth));
        lenient().when(toolsListBaseline.withRemovedHeaders(anyList())).thenReturn(mutatedRequest);
        lenient().when(toolsListBaseline.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
        lenient().when(mutatedRequest.withRemovedHeaders(anyList())).thenReturn(mutatedRequest);
        lenient().when(mutatedRequest.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
    }

    private void stubSingleProbeChain() {
        lenient().when(request.withRemovedHeaders(anyList())).thenReturn(request);
        lenient().when(request.withHeader(anyString(), anyString())).thenReturn(request);
        lenient().when(request.withBody(anyString())).thenReturn(probeRequest);
    }

    private void stubAllProbeResponses(int statusCode, String body) {
        HttpRequestResponse response = httpRequestResponse(statusCode, body);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(response);
    }

    private void wireMutationChainOn(HttpRequest target, List<HttpHeader> currentHeaders) {
        lenient().when(target.headers()).thenReturn(List.copyOf(currentHeaders));
        lenient().when(target.withRemovedHeaders(anyList())).thenAnswer(invocation -> {
            List<HttpHeader> toRemove = invocation.getArgument(0);
            List<HttpHeader> next = new ArrayList<>(currentHeaders);
            next.removeIf(existing -> toRemove.stream()
                    .anyMatch(removed -> removed.name().equalsIgnoreCase(existing.name())));
            HttpRequest mutated = mock(HttpRequest.class);
            wireMutationChainOn(mutated, next);
            return mutated;
        });
        lenient().when(target.withHeader(anyString(), anyString())).thenAnswer(invocation -> {
            String name = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            List<HttpHeader> next = new ArrayList<>(currentHeaders);
            next.removeIf(existing -> existing.name().equalsIgnoreCase(name));
            next.add(httpHeader(name, value));
            HttpRequest mutated = mock(HttpRequest.class);
            wireMutationChainOn(mutated, next);
            return mutated;
        });
        lenient().when(target.withBody(anyString())).thenAnswer(invocation -> {
            HttpRequest mutated = mock(HttpRequest.class);
            wireMutationChainOn(mutated, new ArrayList<>(currentHeaders));
            return mutated;
        });
    }

    /** A transport-layer failure: Burp returns an HttpRequestResponse with a null response. */
    private HttpRequestResponse transientFailure() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        lenient().when(rr.response()).thenReturn(null);
        return rr;
    }

    private HttpRequestResponse httpRequestResponse(int statusCode, String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn("application/json");
        return rr;
    }

    private HttpHeader httpHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }

    private AuditIssue issueWithName(String name) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        return issue;
    }
}
