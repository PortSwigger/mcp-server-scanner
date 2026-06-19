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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveHiddenMethodCheckTest {

    private static final String METHOD_NOT_FOUND_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
    private static final String SUCCESS_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    private static final String BASELINE_SUCCESS_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}";
    private static final String INVALID_PARAMS_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}";
    private static final String INTERNAL_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}";
    private static final String SERVER_DEFINED_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32001,\"message\":\"server-defined\"}}";
    private static final String TOOL_IS_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"err\"}],\"isError\":true}}";

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
    private HttpRequest mutatedRequest;

    @Mock
    private HttpService httpService;

    @Mock
    private ScanCheckSettings settings;

    private McpActiveHiddenMethodCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveHiddenMethodCheck(settings);
    }

    @Test
    void descriptor_exposesHiddenMethodMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("hidden-method");
        assertThat(descriptor.displayName()).isEqualTo("MCP Hidden Method Exposed");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        // T14: switched from PER_HOST to PER_REQUEST. PER_HOST was silently
        // skipped by Burp's audit pipeline in "Active Scan from captured
        // request" mode. Internal HostDedup prevents per-insertion-point storms.
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
    }

    @Test
    void descriptor_isVulnFirstWithTrimmedReferences() {
        CheckDescriptor descriptor = check.descriptor();

        // Vuln-first: drop wordlist namespaces, the -32601 explanation, and tier vocabulary.
        assertThat(descriptor.description()).doesNotStartWith("Probes");
        assertThat(descriptor.description()).doesNotContain("-32601");
        assertThat(descriptor.description()).doesNotContain("separator-confusion");
        // References: keep jsonrpc.org spec, MCP basic spec, CWE-749 (exposed dangerous method).
        assertThat(descriptor.references()).containsExactly(
                "https://www.jsonrpc.org/specification",
                "https://modelcontextprotocol.io/specification/2025-11-25/basic",
                "https://cwe.mitre.org/data/definitions/749.html");
    }

    @Test
    void remediationAddsInternalEndpointGuidanceAndDropsLeakSentence() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.remediation()).containsIgnoringCase("admin");
        assertThat(issue.remediation()).doesNotContain("leaks the existence");
    }

    @Test
    void descriptor_uses_PER_REQUEST_dispatch() {
        // T14: PER_HOST is silently skipped by Burp's audit pipeline in
        // "Active Scan from captured request" mode. HostDedup
        // tryClaim/releaseIfHttpLayerErrored prevents the wordlist firing
        // multiple times per host now that dispatch is per-insertion-point.
        assertThat(check.descriptor().scope()).isEqualTo(ScanCheckType.PER_REQUEST);
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("hidden-method", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void skipsNonMcpTraffic() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\"hello\":\"world\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void engages_onResourcesReadBaseline() {
        stubMcpRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///x\"}}");
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
    }

    @Test
    void engages_onPromptsGetBaseline() {
        stubMcpRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}");
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
    }

    @Test
    void firesExposedIssueWhenAnyProbeReturnsSuccess() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue exposed = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(exposed.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(exposed.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(exposed.detail())
                .contains("admin.config -&gt; success")
                .contains("debug.info -&gt; success");
    }

    @Test
    void noIssueWhenAllProbesReturnInvalidParams() {
        // FP-neg: -32602 is returned by real frameworks for non-existent methods, so it must
        // no longer be treated as "recognised".
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, INVALID_PARAMS_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void noIssueWhenAllProbesReturnInternalError() {
        // FP-neg: -32603 is a generic exception code returned for unknown methods too.
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, INTERNAL_ERROR_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void firesTentativeInformationIssueWhenOnlyServerDefinedCodesAreFound() {
        // TP-pos: a server-defined code (-32001) signals a deliberate handler and is raised at
        // INFORMATION/TENTATIVE.
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, SERVER_DEFINED_ERROR_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("Recognised");
        assertThat(issue.detail()).doesNotContain("Exposed");
        assertThat(issue.detail())
                .contains("admin.config -&gt; -32001 (server-defined error code)")
                .contains("debug.info -&gt; -32001 (server-defined error code)");
    }

    @Test
    void labelsToolsDotListAsSeparatorConfusionOnSuspiciousHit() {
        // tools.list returns a successful tools/list-shaped response. The new label must call out
        // separator-confusion / dispatcher normalisation rather than "admin method exposure".
        stubMcpRequest("example.test", 8080, false);
        when(request.withBody(anyString())).thenAnswer(invocation -> {
            String body = invocation.getArgument(0);
            HttpRequest req = mock(HttpRequest.class);
            lenient().when(req.headers()).thenReturn(List.of());
            // Tag the request with the method via the body so the probe can be identified later.
            lenient().when(req.bodyToString()).thenReturn(body);
            return req;
        });
        // Only tools.list (or mcp.tools/list) is allowed to succeed.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest req = invocation.getArgument(0);
            String body = req.bodyToString();
            if (body.contains("\"tools.list\"") || body.contains("\"mcp.tools/list\"")) {
                return httpRequestResponse(200, SUCCESS_BODY, null);
            }
            return httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.detail()).contains("tools.list -&gt; success");
        assertThat(issue.detail()).doesNotContain("separator-confusion");
    }

    @Test
    void combinesExposedAndRecognisedFindingsIntoSingleIssue() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse exposed = httpRequestResponse(200, SUCCESS_BODY, null);
        HttpRequestResponse recognised = httpRequestResponse(200, SERVER_DEFINED_ERROR_BODY, null);
        // admin.config is a non-demoted exposure, so the combined issue stays MEDIUM.
        stubProbeResponsesByMethod(
                Map.of("admin.config", exposed, "debug.info", recognised),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.detail()).contains("Exposed", "Recognised");
        assertThat(issue.detail()).doesNotContain("no error envelope", "-32601");
    }

    @Test
    void emitsIssueWhenAllProbesReturnResultIsErrorTrue_methodsRecognised() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, TOOL_IS_ERROR_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isNotEmpty();
        assertThat(singleIssueByName(result, "MCP Hidden Method Exposed")).isNotNull();
    }

    @Test
    void emitsNoIssueWhenAllProbesReturnMethodNotFound() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void dedupsRepeatedScansAgainstSameHost() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));

        AuditResult firstRun = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult secondRun = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(firstRun.auditIssues()).isNotEmpty();
        assertThat(secondRun.auditIssues()).isEmpty();
    }

    @Test
    void reprobesWhenAuthFingerprintChangesForSameHost() {
        HttpHeader tokenA = httpHeader("Authorization", "Bearer token-A");
        stubMcpToolsCallRequest(tokenA);
        stubAllProbesNotFound();
        int wordlistSize = HiddenMethodWordlist.PROBES.size();

        check.doCheck(baseRequestResponse, insertionPoint, http);

        HttpHeader tokenB = httpHeader("Authorization", "Bearer token-B");
        HostFixture rebound = stubAdditionalHost("example.test", 8080, false);
        when(rebound.request().headers()).thenReturn(List.of(tokenB));
        when(rebound.request().withBody(anyString())).thenReturn(mutatedRequest);

        check.doCheck(rebound.requestResponse(), insertionPoint, http);

        verify(http, atLeast(wordlistSize * 2)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void skipsReprobeWhenAuthFingerprintUnchanged() {
        HttpHeader tokenA = httpHeader("Authorization", "Bearer token-A");
        stubMcpToolsCallRequest(tokenA);
        stubAllProbesNotFound();
        int wordlistSize = HiddenMethodWordlist.PROBES.size();

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.doCheck(baseRequestResponse, insertionPoint, http);

        verify(http, times(wordlistSize)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void firesPerDistinctHost() {
        HostFixture hostA = stubAdditionalHost("host-a.test", 8080, false);
        HostFixture hostB = stubAdditionalHost("host-b.test", 8080, false);
        HttpRequest mutatedA = mock(HttpRequest.class);
        HttpRequest mutatedB = mock(HttpRequest.class);
        HttpRequestResponse exposed = httpRequestResponse(200, SUCCESS_BODY, null);
        lenient().when(hostA.request().withBody(anyString())).thenReturn(mutatedA);
        lenient().when(hostB.request().withBody(anyString())).thenReturn(mutatedB);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(exposed);

        AuditResult firstResult = check.doCheck(hostA.requestResponse(), insertionPoint, http);
        AuditResult secondResult = check.doCheck(hostB.requestResponse(), insertionPoint, http);

        assertThat(firstResult.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
        assertThat(secondResult.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
    }

    @Test
    void echoExposedAloneEmitsInformationNotMedium() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("echo", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.detail()).contains("echo");
    }

    @Test
    void testExposedAloneEmitsInformationNotMedium() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("test", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.detail()).contains("test");
    }

    @Test
    void adminConfigExposedAlongsideEchoStillEmitsMedium() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse success = httpRequestResponse(200, SUCCESS_BODY, null);
        stubProbeResponsesByMethod(
                Map.of("admin.config", success, "echo", success),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.detail()).contains("admin.config").contains("echo");
    }

    @Test
    void does_not_poison_dedup_on_early_empty_run() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse httpError = httpRequestResponse(503, "", null);
        HttpRequestResponse notFound = httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null);
        HttpRequestResponse success = httpRequestResponse(200, SUCCESS_BODY, null);
        int wordlistSize = HiddenMethodWordlist.PROBES.size();
        when(request.withBody(anyString())).thenReturn(mutatedRequest);
        when(http.sendRequest(mutatedRequest))
                .thenAnswer(invocation -> httpError);

        AuditResult firstRun = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(firstRun.auditIssues()).isEmpty();

        stubProbeResponsesByMethod(Map.of("debug.info", success), notFound);

        AuditResult secondRun = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(secondRun.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
        verify(http, atLeast(wordlistSize * 2)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void dedups_within_session_after_successful_probe_sequence() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = new McpActiveHiddenMethodCheck(settings, eventLog);
        stubMcpRequest("example.test", 8080, false);
        stubAllProbesNotFound();
        int wordlistSize = HiddenMethodWordlist.PROBES.size();

        check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult secondRun = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(secondRun.auditIssues()).isEmpty();
        verify(http, times(wordlistSize)).sendRequest(any(HttpRequest.class));
        verify(eventLog, atLeastOnce()).info(contains("decision: skipped"));
        verify(eventLog, atLeastOnce()).info(contains("already probed host"));
    }

    @Test
    void does_not_dedup_when_probe_sequence_had_http_layer_error() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse httpError = httpRequestResponse(503, "", null);
        int wordlistSize = HiddenMethodWordlist.PROBES.size();
        when(request.withBody(anyString())).thenReturn(mutatedRequest);
        when(http.sendRequest(mutatedRequest)).thenReturn(httpError);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.doCheck(baseRequestResponse, insertionPoint, http);

        verify(http, atLeast(wordlistSize * 2)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void still_emits_finding_when_wordlist_hits() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("debug.info", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
    }

    // Item 18: system.* introspection method demotion ----------------------------

    @Test
    void systemListMethodsExposedAloneEmitsInformationAndTentative() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("system.listMethods", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("system.listMethods");
    }

    @Test
    void systemMethodHelpExposedAloneEmitsInformationAndTentative() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("system.methodHelp", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("system.methodHelp");
    }

    @Test
    void systemMethodSignatureExposedAloneEmitsInformationAndTentative() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("system.methodSignature", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("system.methodSignature");
    }

    @Test
    void systemListMethodsAlongsideAdminConfigStillEmitsMediumFirm() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse success = httpRequestResponse(200, SUCCESS_BODY, null);
        stubProbeResponsesByMethod(
                Map.of("system.listMethods", success, "admin.config", success),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void allThreeSystemIntrospectionMethodsExposedEmitsInformationAndTentative() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse success = httpRequestResponse(200, SUCCESS_BODY, null);
        stubProbeResponsesByMethod(
                Map.of("system.listMethods", success,
                       "system.methodHelp", success,
                       "system.methodSignature", success),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void systemIntrospectionMixedWithEchoStillEmitsInformationAndTentative() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse success = httpRequestResponse(200, SUCCESS_BODY, null);
        stubProbeResponsesByMethod(
                Map.of("system.listMethods", success, "echo", success),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void rpcDiscoverExposedAloneEmitsInformationAndTentative() {
        // Open-RPC stock introspection: rpc.discover is a framework default, low impact.
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("rpc.discover", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("rpc.discover");
    }

    @Test
    void rpcDescribeExposedAloneEmitsInformationAndTentative() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("rpc.describe", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("rpc.describe");
    }

    @Test
    void rpcDiscoverAlongsideAdminConfigStillEmitsMediumFirm() {
        stubMcpRequest("example.test", 8080, false);
        HttpRequestResponse success = httpRequestResponse(200, SUCCESS_BODY, null);
        stubProbeResponsesByMethod(
                Map.of("rpc.discover", success, "admin.config", success),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void nonIntrospectionMethodExposedKeepsFirmConfidence() {
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponsesByMethod(
                Map.of("debug.info", httpRequestResponse(200, SUCCESS_BODY, null)),
                httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleIssueByName(result, "MCP Hidden Method Exposed");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    // End Item 18 ---------------------------------------------------------------

    @Test
    void does_not_emit_when_wordlist_misses_everything() {
        stubMcpRequest("example.test", 8080, false);
        stubAllProbesNotFound();
        int wordlistSize = HiddenMethodWordlist.PROBES.size();

        AuditResult firstRun = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult secondRun = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(firstRun.auditIssues()).isEmpty();
        assertThat(secondRun.auditIssues()).isEmpty();
        verify(http, times(wordlistSize)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void skipsProbingWhenBaselineIsJsonRpcError() {
        // A4 FP-neg: a pre-init / errored baseline means the captured session is not live, so
        // no probes are sent and no issue is raised.
        stubMcpRequest("example.test", 8080, false);
        stubBaselineResponse(baseRequestResponse,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32002,\"message\":\"not initialized\"}}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void doesNotConsumeDedupClaimWhenBaselineNotInitialized() {
        // A4: the skip must happen before hostDedup.tryClaim so a later healthy invocation
        // against the same host still probes.
        stubMcpRequest("example.test", 8080, false);
        stubBaselineResponse(baseRequestResponse,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32002,\"message\":\"not initialized\"}}");

        AuditResult firstRun = check.doCheck(baseRequestResponse, insertionPoint, http);
        assertThat(firstRun.auditIssues()).isEmpty();

        stubBaselineResponse(baseRequestResponse, BASELINE_SUCCESS_BODY);
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));
        AuditResult secondRun = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(secondRun.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
    }

    @Test
    void probesWhenBaselineIsStrictMcpSuccess() {
        // A4 TP-pos: a healthy baseline success drives the wordlist as before.
        stubMcpRequest("example.test", 8080, false);
        stubProbeResponse(httpRequestResponse(200, SUCCESS_BODY, null));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Hidden Method Exposed");
        verify(http, atLeastOnce()).sendRequest(any(HttpRequest.class));
    }

    private void stubMcpRequest(String host, int port, boolean secure) {
        stubMcpRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{}}}",
                host, port, secure);
    }

    private void stubMcpToolsCallRequest(HttpHeader... headers) {
        stubMcpRequest("example.test", 8080, false);
        lenient().when(request.headers()).thenReturn(List.of(headers));
    }

    private void stubAllProbesNotFound() {
        stubProbeResponse(httpRequestResponse(200, METHOD_NOT_FOUND_BODY, null));
    }

    private HttpHeader httpHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }

    private void stubMcpRequestWithBody(String body) {
        stubMcpRequestWithBody(body, "example.test", 8080, false);
    }

    private void stubMcpRequestWithBody(String body, String host, int port, boolean secure) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(body);
        lenient().when(request.headers()).thenReturn(List.of());
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.host()).thenReturn(host);
        lenient().when(httpService.port()).thenReturn(port);
        lenient().when(httpService.secure()).thenReturn(secure);
        stubBaselineResponse(baseRequestResponse, BASELINE_SUCCESS_BODY);
    }

    private void stubBaselineResponse(HttpRequestResponse rr, String body) {
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn("application/json");
    }

    private void stubProbeResponse(HttpRequestResponse response) {
        when(request.withBody(anyString())).thenReturn(mutatedRequest);
        when(http.sendRequest(mutatedRequest)).thenReturn(response);
    }

    private void stubProbeResponsesByMethod(Map<String, HttpRequestResponse> overrides,
                                            HttpRequestResponse defaultResponse) {
        Map<HttpRequest, HttpRequestResponse> mutatedToResponse = new HashMap<>();
        Pattern methodPattern = Pattern.compile("\"method\"\\s*:\\s*\"([^\"]+)\"");
        when(request.withBody(anyString())).thenAnswer(invocation -> {
            String body = invocation.getArgument(0);
            Matcher matcher = methodPattern.matcher(body);
            if (!matcher.find()) {
                throw new AssertionError("Probe body missing method field: " + body);
            }
            String method = matcher.group(1);
            HttpRequest perMethodRequest = mock(HttpRequest.class);
            mutatedToResponse.put(perMethodRequest,
                    overrides.getOrDefault(method, defaultResponse));
            return perMethodRequest;
        });
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            HttpRequestResponse response = mutatedToResponse.get(sent);
            if (response == null) {
                throw new AssertionError("Unexpected HttpRequest passed to sendRequest");
            }
            return response;
        });
    }

    private HostFixture stubAdditionalHost(String host, int port, boolean secure) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        lenient().when(rr.request()).thenReturn(req);
        lenient().when(req.method()).thenReturn("POST");
        lenient().when(req.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{}}}");
        lenient().when(req.headers()).thenReturn(List.of());
        lenient().when(req.httpService()).thenReturn(service);
        lenient().when(service.host()).thenReturn(host);
        lenient().when(service.port()).thenReturn(port);
        lenient().when(service.secure()).thenReturn(secure);
        stubBaselineResponse(rr, BASELINE_SUCCESS_BODY);
        return new HostFixture(rr, req);
    }

    private record HostFixture(HttpRequestResponse requestResponse, HttpRequest request) {}

    private static HttpRequestResponse httpRequestResponse(int statusCode, String body, String contentType) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn(contentType);
        return rr;
    }

    private AuditIssue singleIssueByName(AuditResult result, String name) {
        return result.auditIssues().stream()
                .filter(issue -> issue.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected issue " + name + " not found"));
    }
}
