package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveAuthBypassCheckTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private HttpRequestResponse baseRequestResponse;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Mock
    private Http http;

    @Mock
    private HttpRequest request;

    @Mock
    private HttpService httpService;

    @Mock
    private ScanCheckSettings settings;

    private McpActiveAuthBypassCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveAuthBypassCheck(settings, NoAuthStrategy::new);
    }

    @Test
    void descriptor_exposesAuthBypassMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("auth-bypass");
        assertThat(descriptor.displayName()).isEqualTo("MCP Authentication Bypass");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("auth-bypass", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void returnsEmptyForNonToolsCallRequest() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void skipsWhenBaselineHasNoAuthBearingHeaders() {
        check = new McpActiveAuthBypassCheck(settings, NoAuthStrategy::new);
        stubTrackingToolsCallRequestWithHeaders(
                httpHeader("Content-Type", "application/json"),
                httpHeader("Mcp-Session-Id", "session-123"));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void reportsAuthNotEnforcedWhenStripProbeSucceeds() {
        // The auth-not-enforced branch is TENTATIVE on every transport: the proxy
        // re-injects Mcp-Session-Id (NON_AUTH_SESSION_HEADERS) so the stripped probe
        // still carries a valid session, demonstrating the server trusts the session
        // id rather than fully anonymous access.
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .anySatisfy(issue -> {
                    assertThat(issue.name()).isEqualTo("MCP Authentication Bypass");
                    assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
                    assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
                });
    }

    @Test
    void authNotEnforcedIsTentativeWithSessionTrustCaveatRegardlessOfTransport() {
        // The local proxy re-injects Mcp-Session-Id on BOTH transports (it is in
        // SseProxyServer.NON_AUTH_SESSION_HEADERS), so the strip-auth probe always
        // reaches the server with a valid post-initialize session even though the
        // Authorization header was genuinely stripped. A positive therefore proves
        // the server does not re-validate the bearer per request (it trusts the
        // session id), not fully anonymous access. The wire behaviour is identical
        // on Streamable HTTP and SSE, so the finding is TENTATIVE and carries the
        // session-trust caveat in every case — transport is no longer a factor.
        check = new McpActiveAuthBypassCheck(
                settings, () -> new BearerTokenAuthStrategy("token"));
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Authentication Bypass");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains(
                "does not re-validate the bearer token on every request");
        assertThat(issue.detail()).contains("Mcp-Session-Id");
    }

    @Test
    void detailDropsInlineSpecMustBlockAndRemediationKeepsValidationGuidance() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue authIssue = singleIssueByName(result, "MCP Authentication Bypass");
        String detail = authIssue.detail();
        // Inline spec-MUST quote block is gone from the detail.
        assertThat(detail).doesNotContain("Violated MCP authorization-spec MUSTs");
        assertThat(detail).doesNotContain("MUST NOT accept any tokens");
        assertThat(detail).doesNotContain("MUST receive a HTTP 401 response");

        String remediation = authIssue.remediation();
        // Remediation keeps validation guidance but drops the inline spec quote and bare CVEs.
        assertThat(remediation).containsIgnoringCase("validate");
        assertThat(remediation).doesNotContain("MUST NOT use sessions for authentication");
        assertThat(remediation).doesNotContain("CVE-2026-33032");
        assertThat(remediation).doesNotContain("CVE-2025-49596");
    }

    @Test
    void detailClaimsOnlyProvenFactAndDropsDeploymentWideGeneralization() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue authIssue = singleIssueByName(result, "MCP Authentication Bypass");
        String detail = authIssue.detail();
        assertThat(detail).contains("executed the tool");
        assertThat(detail).containsIgnoringCase("public");
        assertThat(detail).doesNotContain("across the deployment");
        assertThat(detail).doesNotContain("every discovered tool");
    }

    @Test
    void descriptorIsVulnFirstWithTrimmedReferences() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.description()).doesNotStartWith("Detects");
        assertThat(descriptor.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#token-passthrough",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking",
                "https://datatracker.ietf.org/doc/html/rfc6750#section-2.1");
    }

    @Test
    void foldsInvalidTokenSuccessesIntoAuthNotEnforcedIssue() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        // STRIP_AUTH fails, EMPTY_BEARER succeeds, GARBAGE_BEARER succeeds, NO_SCHEME fails.
        // Identity-aware: respond based on what Authorization header value the probe sent.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if ("Bearer ".equals(auth) || "Bearer not_a_real_token_12345".equals(auth)) {
                return httpRequestResponse(200, "{\"jsonrpc\":\"2.0\",\"result\":{}}");
            }
            return httpRequestResponse(401, "{\"error\":\"unauthorized\"}");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue authIssue = singleIssueByName(result, "MCP Authentication Bypass");
        assertThat(authIssue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(authIssue.detail()).contains("empty bearer token", "invalid bearer token");
        assertThat(authIssue.detail()).doesNotContain("EMPTY_BEARER", "GARBAGE_BEARER");
        assertThat(result.auditIssues()).noneMatch(issue -> issue.name().equals("MCP Weak Token Validation"));
    }

    @Test
    void emitsSingleAuthNotEnforcedIssueListingAllSuccessfulProbes() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        long authIssueCount = result.auditIssues().stream()
                .filter(issue -> issue.name().equals("MCP Authentication Bypass"))
                .count();
        assertThat(authIssueCount).isEqualTo(1);
        assertThat(result.auditIssues()).noneMatch(issue -> issue.name().equals("MCP Weak Token Validation"));
    }

    @Test
    void returnsEmptyWhenAllProbesFail() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerRejectingAllProbes();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void returnsEmptyWhen200ResponseBodyContainsResultIsErrorTrue() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"invalid input\"}],\"isError\":true}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void returnsEmptyWhen200ResponseBodyContainsJsonRpcError() {
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Authorization", "Bearer valid"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void firesWhenAuthIsContributedByCustomHeaderStrategy() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "abc"));
        check = new McpActiveAuthBypassCheck(settings, () -> customAuth);
        stubTrackingToolsCallRequestWithHeaders(httpHeader("X-Api-Key", "abc"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isNotEmpty();
    }

    @Test
    void runsForCustomHeaderAuthAndFindsGarbageHeaderAccepted() {
        AuthStrategy customAuth = new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "secret123"));
        check = new McpActiveAuthBypassCheck(settings, () -> customAuth);
        stubTrackingToolsCallRequestWithHeaders(httpHeader("X-Api-Key", "secret123"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Authentication Bypass");
        assertThat(issue.detail()).contains("invalid X-Api-Key header");
        assertThat(issue.detail()).doesNotContain("GARBAGE_X-API-KEY");
        assertThat(issue.detail()).doesNotContain("secret123");
    }

    @Test
    void recognisesCookieAsAuthBearingHeader() {
        check = new McpActiveAuthBypassCheck(settings, NoAuthStrategy::new);
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Cookie", "auth=foo"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isNotEmpty();
    }

    @Test
    void gateIgnoresMcpSessionIdAlone() {
        check = new McpActiveAuthBypassCheck(settings, NoAuthStrategy::new);
        stubTrackingToolsCallRequestWithHeaders(httpHeader("Mcp-Session-Id", "session-123"));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void firesWhenAuthorizationHeaderHasMixedCase() {
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("token"));
        stubTrackingToolsCallRequestWithHeaders(httpHeader("authorization", "Bearer x"));
        stubServerAcceptingAllProbes("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isNotEmpty();
    }

    @Test
    void noFalsePositiveAgainstSessionBoundServerWhenAuthorizationStrippedButSessionSurvives() {
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("valid-token"));
        stubSessionBoundToolsCallRequest(
                httpHeader("Authorization", "Bearer valid-token"),
                httpHeader("Mcp-Session-Id", "session-abc"));
        stubSessionBoundServer();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void emits_one_issue_per_server_across_multiple_tool_call_invocations() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("valid"), eventLog);

        InvocationFixture exec = invocationFor("exec", "localhost", 8080);
        InvocationFixture read = invocationFor("read", "localhost", 8080);
        InvocationFixture write = invocationFor("write", "localhost", 8080);

        AuditResult first = check.doCheck(exec.requestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(read.requestResponse, insertionPoint, http);
        AuditResult third = check.doCheck(write.requestResponse, insertionPoint, http);

        long totalIssues = totalAuthBypassIssues(first, second, third);
        assertThat(totalIssues).isEqualTo(1);
        verify(eventLog, atLeastOnce()).info(contains("auth bypass already reported for this server"));
    }

    @Test
    void emits_separate_issues_for_distinct_servers() {
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("valid"));

        InvocationFixture serverA = invocationFor("exec", "host-a.example", 8080);
        InvocationFixture serverB = invocationFor("exec", "host-b.example", 8080);

        AuditResult first = check.doCheck(serverA.requestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(serverB.requestResponse, insertionPoint, http);

        assertThat(totalAuthBypassIssues(first, second)).isEqualTo(2);
    }

    @Test
    void emits_separate_issues_when_auth_fingerprint_changes() {
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("valid"));

        InvocationFixture firstAuth = invocationFor("exec", "localhost", 8080,
                httpHeader("Authorization", "Bearer first-token"));
        InvocationFixture secondAuth = invocationFor("exec", "localhost", 8080,
                httpHeader("Authorization", "Bearer second-token"));

        AuditResult first = check.doCheck(firstAuth.requestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(secondAuth.requestResponse, insertionPoint, http);

        assertThat(totalAuthBypassIssues(first, second)).isEqualTo(2);
    }

    @Test
    void concurrent_dispatch_emits_exactly_one_issue() throws Exception {
        int threadCount = 5;
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("valid"));

        List<InvocationFixture> fixtures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            fixtures.add(invocationFor("tool-" + i, "localhost", 8080));
        }

        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        List<Future<AuditResult>> futures = new ArrayList<>();
        for (InvocationFixture fixture : fixtures) {
            futures.add(pool.submit(() -> {
                startLatch.await();
                return check.doCheck(fixture.requestResponse, insertionPoint, http);
            }));
        }

        startLatch.countDown();
        long totalIssues = 0;
        for (Future<AuditResult> future : futures) {
            totalIssues += future.get(5, TimeUnit.SECONDS).auditIssues().stream()
                    .filter(issue -> issue.name().equals("MCP Authentication Bypass"))
                    .count();
        }
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        assertThat(totalIssues).isEqualTo(1);
    }

    @Test
    void does_not_emit_when_no_bypass_succeeds_and_subsequent_invocations_still_probe() {
        check = new McpActiveAuthBypassCheck(settings, () -> new BearerTokenAuthStrategy("valid"));

        InvocationFixture exec = invocationFor("exec", "localhost", 8080, true);
        AuditResult firstRun = check.doCheck(exec.requestResponse, insertionPoint, http);
        assertThat(firstRun.auditIssues()).isEmpty();

        InvocationFixture read = invocationFor("read", "localhost", 8080);
        AuditResult secondRun = check.doCheck(read.requestResponse, insertionPoint, http);
        assertThat(secondRun.auditIssues()).isNotEmpty();
    }

    // ---------- Server stub helpers ----------

    private void stubServerAcceptingAllProbes(String successBody) {
        HttpRequestResponse success = httpRequestResponse(200, successBody);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(success);
    }

    private void stubServerRejectingAllProbes() {
        HttpRequestResponse rejection = httpRequestResponse(401, "{\"error\":\"unauthorized\"}");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(rejection);
    }

    // ---------- Request stub helpers ----------

    /**
     * Stubs {@code baseRequestResponse.request()} with a tools/call tracking request that
     * correctly propagates header mutations (withHeader / withRemovedHeaders) through
     * {@link #wireMutationChainOn}. The server stub can then inspect what headers were actually
     * sent rather than relying on positional call order.
     */
    private void stubTrackingToolsCallRequestWithHeaders(HttpHeader... headers) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"cmd\":\"ls\"}}}");
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
        wireMutationChainOn(request, new ArrayList<>(List.of(headers)));
    }

    private void stubSessionBoundToolsCallRequest(HttpHeader... headers) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"cmd\":\"ls\"}}}");
        lenient().when(request.headers()).thenReturn(List.of(headers));
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
        wireMutationChainOn(request, new ArrayList<>(List.of(headers)));
    }

    private void wireMutationChainOn(HttpRequest target, List<HttpHeader> currentHeaders) {
        lenient().when(target.headers()).thenReturn(List.copyOf(currentHeaders));
        lenient().when(target.headerValue(anyString())).thenAnswer(inv ->
                headerValueIgnoreCase(currentHeaders, inv.getArgument(0)));
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
    }

    private static String headerValueIgnoreCase(List<HttpHeader> headers, String name) {
        return headers.stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(HttpHeader::value)
                .findFirst()
                .orElse(null);
    }

    private void stubSessionBoundServer() {
        lenient().when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            return serverReplyFor(sent);
        });
    }

    private HttpRequestResponse serverReplyFor(HttpRequest sent) {
        if (carriesSession(sent)) {
            return httpRequestResponse(200, "{\"jsonrpc\":\"2.0\",\"result\":{}}");
        }
        return httpRequestResponse(401, "{\"error\":\"unauthorized\"}");
    }

    private boolean carriesSession(HttpRequest sent) {
        return sent.headers().stream()
                .anyMatch(header -> header.name().equalsIgnoreCase("Mcp-Session-Id"));
    }

    // ---------- Multi-invocation fixture ----------

    private static long totalAuthBypassIssues(AuditResult... results) {
        long count = 0;
        for (AuditResult result : results) {
            count += result.auditIssues().stream()
                    .filter(issue -> issue.name().equals("MCP Authentication Bypass"))
                    .count();
        }
        return count;
    }

    private InvocationFixture invocationFor(String toolName, String host, int port,
                                            HttpHeader... extraHeaders) {
        return invocationFor(toolName, host, port, false, extraHeaders);
    }

    private InvocationFixture invocationFor(String toolName, String host, int port, boolean rejectAll,
                                            HttpHeader... extraHeaders) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(httpHeader("Authorization", "Bearer valid"));
        for (HttpHeader extra : extraHeaders) {
            headers.removeIf(existing -> existing.name().equalsIgnoreCase(extra.name()));
            headers.add(extra);
        }
        when(rr.request()).thenReturn(req);
        lenient().when(req.method()).thenReturn("POST");
        lenient().when(req.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\""
                        + toolName + "\",\"arguments\":{}}}");
        lenient().when(req.httpService()).thenReturn(service);
        lenient().when(service.secure()).thenReturn(false);
        lenient().when(service.host()).thenReturn(host);
        lenient().when(service.port()).thenReturn(port);
        wireMutationChainOnFixture(req, headers, http,
                rejectAll
                        ? httpRequestResponse(401, "{\"error\":\"unauthorized\"}")
                        : httpRequestResponse(200, "{\"jsonrpc\":\"2.0\",\"result\":{}}"));
        return new InvocationFixture(rr, req);
    }

    /**
     * Wires the mutation chain on a fixture request and registers a uniform probe reply.
     * Each mutated mock gets the same reply so the fixture simulates a server that accepts
     * (or rejects) all probes uniformly — which is sufficient for dedup / concurrency tests.
     */
    private void wireMutationChainOnFixture(HttpRequest target, List<HttpHeader> currentHeaders,
                                            Http http, HttpRequestResponse probeReply) {
        lenient().when(target.headers()).thenReturn(List.copyOf(currentHeaders));
        lenient().when(target.headerValue(anyString())).thenAnswer(inv ->
                headerValueIgnoreCase(currentHeaders, inv.getArgument(0)));
        lenient().when(target.withRemovedHeaders(anyList())).thenAnswer(invocation -> {
            List<HttpHeader> toRemove = invocation.getArgument(0);
            List<HttpHeader> next = new ArrayList<>(currentHeaders);
            next.removeIf(existing -> toRemove.stream()
                    .anyMatch(removed -> removed.name().equalsIgnoreCase(existing.name())));
            HttpRequest mutated = mock(HttpRequest.class);
            wireMutationChainOnFixture(mutated, next, http, probeReply);
            return mutated;
        });
        lenient().when(target.withHeader(anyString(), anyString())).thenAnswer(invocation -> {
            String name = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            List<HttpHeader> next = new ArrayList<>(currentHeaders);
            next.removeIf(existing -> existing.name().equalsIgnoreCase(name));
            next.add(httpHeader(name, value));
            HttpRequest mutated = mock(HttpRequest.class);
            wireMutationChainOnFixture(mutated, next, http, probeReply);
            lenient().when(http.sendRequest(mutated)).thenReturn(probeReply);
            return mutated;
        });
    }

    private record InvocationFixture(HttpRequestResponse requestResponse, HttpRequest request) {}

    // ---------- Response and header builders ----------

    private HttpRequestResponse httpRequestResponse(int statusCode, String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        return rr;
    }

    private HttpHeader httpHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }

    private AuditIssue singleIssueByName(AuditResult result, String name) {
        return result.auditIssues().stream()
                .filter(issue -> issue.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected issue " + name + " not found"));
    }
}
