package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
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
import java.util.TreeMap;

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
class McpActiveDnsRebindingCheckTest {

    private static final String JSONRPC_RESULT_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    private static final String JSONRPC_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"bad\"}}";
    private static final String DNS_REBINDING_ISSUE_NAME = "MCP DNS Rebinding";
    private static final String ORIGIN_VALIDATION_ISSUE_NAME = "MCP Origin Header Validation";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpService httpService;
    @Mock private ScanCheckSettings settings;

    private McpActiveDnsRebindingCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveDnsRebindingCheck(settings);
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
    void allProbesRejected_returnsEmpty() {
        stubTrackingMcpToolsCallRequest();
        stubServerRejectingAllProbes();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void engages_onResourcesReadBaseline() {
        stubTrackingMcpRequest(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///x\"}}");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
    }

    @Test
    void engages_onPromptsGetBaseline() {
        stubTrackingMcpRequest(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
    }

    @Test
    void hostileOriginAccepted_emitsOriginValidationIssue() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("Origin: http://evil.example");
        assertThat(issue.detail()).doesNotContain("<b>References</b>");
        assertThat(issue.definition().background())
                .isNotEmpty()
                .contains("CWE-346: Origin Validation Error")
                .contains("https://modelcontextprotocol.io");
    }

    @Test
    void nullOriginAccepted_emitsOriginValidationIssue() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingOnlyProbe(ProbeId.NULL_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
        assertThat(issue.detail()).contains("Origin: null");
    }

    @Test
    void hostOverrideAccepted_producesDnsRebindingFinding() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("Host: attacker.example");
        assertThat(issue.definition().background())
                .isNotEmpty()
                .contains("CWE-350")
                .contains("https://nvd.nist.gov/vuln/detail/CVE-2025-49596");
    }

    @Test
    void originOnlyAccepted_producesOriginValidationFindingNotDnsRebinding() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingProbes(ProbeId.HOSTILE_ORIGIN, ProbeId.NULL_ORIGIN, ProbeId.ATTACKER_DOMAIN_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
        assertThat(issue.name()).doesNotContain("DNS Rebinding");
    }

    @Test
    void originOnlyAccepted_detailStatesValidCredentialsReplayed() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        String detail = result.auditIssues().get(0).detail();
        assertThat(detail.toLowerCase()).contains("credential");
        assertThat(detail).containsAnyOf(
                "valid user credentials",
                "valid credentials",
                "the original request's credentials",
                "authenticated session"
        );
    }

    @Test
    void hostAndOriginBothAccepted_emitsBothIssues() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingProbes(ProbeId.HOSTILE_ORIGIN, ProbeId.NULL_ORIGIN,
                ProbeId.ATTACKER_DOMAIN_ORIGIN, ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(2);
        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .containsExactlyInAnyOrder(DNS_REBINDING_ISSUE_NAME, ORIGIN_VALIDATION_ISSUE_NAME);
    }

    @Test
    void hostileOriginRejectedButHostUnvalidated_doesNotFireDnsRebinding() {
        stubTrackingMcpToolsCallRequest();
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isHostileOriginProbe(sent)) {
                return httpRequestResponse(403, "Forbidden", "text/plain");
            }
            return httpRequestResponse(200, JSONRPC_RESULT_BODY, "application/json");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .extracting(AuditIssue::name)
                .doesNotContain(DNS_REBINDING_ISSUE_NAME);
    }

    @Test
    void browserShapedAttack_combinedHostAndOriginAccepted_firesDnsRebinding() {
        // Models a server that rejects every Origin-only probe (so we test the
        // Host-override pathway in isolation) and only accepts a request that carries
        // BOTH Host: attacker.example AND Origin: http://attacker.example together —
        // the shape the fix's combined probe sends and the shape a real
        // browser-driven DNS rebinding attack would produce. The default tracking
        // host is "localhost", so the finding is MEDIUM.
        stubTrackingMcpToolsCallRequest();
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isCombinedHostAndOriginProbe(sent)) {
                return httpRequestResponse(200, JSONRPC_RESULT_BODY, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    private static boolean isHostileOriginProbe(HttpRequest sent) {
        String origin = sent.headerValue("Origin");
        if (origin == null) {
            return false;
        }
        return "http://evil.example".equals(origin)
                || "null".equals(origin)
                || origin.startsWith("http://attacker.example");
    }

    private static boolean isCombinedHostAndOriginProbe(HttpRequest sent) {
        return "attacker.example".equals(sent.headerValue("Host"))
                && "http://attacker.example".equals(sent.headerValue("Origin"));
    }

    @Test
    void multipleOriginProbesAccepted_emitsSingleOriginIssueListingAll() {
        stubTrackingMcpToolsCallRequest();
        stubServerAcceptingProbes(ProbeId.HOSTILE_ORIGIN, ProbeId.NULL_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        String detail = result.auditIssues().get(0).detail();
        assertThat(detail).contains("Origin: http://evil.example");
        assertThat(detail).contains("Origin: null");
    }

    @Test
    void sseFramedResponseAccepted_isUnwrappedAndDetected() {
        stubTrackingMcpToolsCallRequest();
        String sseBody = "event: message\ndata: " + JSONRPC_RESULT_BODY + "\n\n";
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_ORIGIN)) {
                return httpRequestResponse(200, sseBody, "text/event-stream");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
    }

    @Test
    void connectionErrorOrFiveXX_isIgnored() {
        stubTrackingMcpToolsCallRequest();
        HttpRequestResponse serverError = httpRequestResponse(503, "Service Unavailable", "text/plain");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(serverError);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void errorResponseBody_isNotVulnerable() {
        stubTrackingMcpToolsCallRequest();
        HttpRequestResponse errorBody = httpRequestResponse(200, JSONRPC_ERROR_BODY, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(errorBody);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void resultWithIsErrorTrue_isNotVulnerable() {
        stubTrackingMcpToolsCallRequest();
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"invalid\"}],\"isError\":true}}";
        HttpRequestResponse toolError = httpRequestResponse(200, body, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(toolError);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void consolidateIssues_returnsKeepExistingForSameDnsRebindingName() {
        AuditIssue existing = issueWithName(DNS_REBINDING_ISSUE_NAME);
        AuditIssue incoming = issueWithName(DNS_REBINDING_ISSUE_NAME);

        assertThat(check.consolidateIssues(existing, incoming)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
    }

    @Test
    void consolidateIssues_returnsKeepExistingForSameOriginValidationName() {
        AuditIssue existing = issueWithName(ORIGIN_VALIDATION_ISSUE_NAME);
        AuditIssue incoming = issueWithName(ORIGIN_VALIDATION_ISSUE_NAME);

        assertThat(check.consolidateIssues(existing, incoming)).isEqualTo(ConsolidationAction.KEEP_EXISTING);
    }

    @Test
    void consolidateIssues_returnsKeepBothWhenDnsRebindingAndOriginValidationCollide() {
        AuditIssue existing = issueWithName(DNS_REBINDING_ISSUE_NAME);
        AuditIssue incoming = issueWithName(ORIGIN_VALIDATION_ISSUE_NAME);

        assertThat(check.consolidateIssues(existing, incoming)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    @Test
    void descriptor_exposesDnsRebindingMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("dns-rebinding");
        assertThat(descriptor.displayName()).isEqualTo("MCP DNS Rebinding / Origin Header Validation");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
        assertThat(descriptor.burpIssueName()).isEmpty();
        assertThat(descriptor.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#security-warning",
                "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w",
                "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49596"
        );
    }

    @Test
    void checkName_returnsDescriptorDisplayName() {
        assertThat(check.checkName()).isEqualTo("MCP DNS Rebinding / Origin Header Validation");
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("dns-rebinding", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void dnsRebindingDemotesToInformationWhenTargetHostIsPublic() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("mcp.example.com");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.detail()).contains("publicly reachable");
    }

    @Test
    void dnsRebindingDemotesToInformationWhenTargetHostIsWildcardAddress() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("0.0.0.0");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(issue.detail()).contains("publicly reachable");
    }

    @Test
    void dnsRebindingKeepsMediumSeverityWhenTargetIsLoopback() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("127.0.0.1");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void dnsRebindingKeepsMediumSeverityWhenTargetIsRfc1918() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("192.168.1.50");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void dnsRebindingKeepsMediumSeverityWhenTargetIsLocalhostLiteral() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("localhost");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void dnsRebindingCapsAtLowWhenBaselineCarriesAuthorizationHeader() {
        stubTrackingMcpRequestWithAuthHeader("Authorization", "Bearer real-session-token");
        when(httpService.host()).thenReturn("127.0.0.1");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
        assertThat(issue.detail().toLowerCase()).contains("credential");
        assertThat(issue.detail()).containsAnyOf(
                "would not possess",
                "would not hold",
                "does not hold",
                "reachable unauthenticated");
    }

    @Test
    void dnsRebindingCapsAtLowWhenBaselineCarriesCookieHeader() {
        stubTrackingMcpRequestWithAuthHeader("Cookie", "session=abc123");
        when(httpService.host()).thenReturn("127.0.0.1");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void dnsRebindingStaysMediumWhenLoopbackBaselineIsUncredentialed() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("127.0.0.1");
        stubServerAcceptingOnlyProbe(ProbeId.HOSTILE_HOST);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
    }

    @Test
    void originValidationStaysLowEvenWhenTargetHostIsLoopback() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("127.0.0.1");
        stubServerAcceptingProbes(ProbeId.HOSTILE_ORIGIN, ProbeId.NULL_ORIGIN, ProbeId.ATTACKER_DOMAIN_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void originValidationStaysLowEvenWhenTargetHostIsPublic() {
        stubTrackingMcpToolsCallRequest();
        when(httpService.host()).thenReturn("mcp.example.com");
        stubServerAcceptingProbes(ProbeId.HOSTILE_ORIGIN, ProbeId.NULL_ORIGIN, ProbeId.ATTACKER_DOMAIN_ORIGIN);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void flags_dns_rebinding_when_origin_rewritten_probe_returns_equivalent_response() {
        String toolsListBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        String toolsListResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"},{\"name\":\"c\"}]}}";
        stubTrackingMcpRequest(toolsListBody);
        stubBaselineResponse(200, toolsListResult, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_ORIGIN)) {
                return httpRequestResponse(200, toolsListResult, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
    }

    @Test
    void does_not_flag_when_toolcall_probe_shares_keys_but_differs_in_content() {
        // tools/call baseline. The rewritten-Host probe returns a 200 MCP success whose
        // result has the SAME top-level keys {content, isError} but DIFFERENT content text
        // (the server rejected the rebind with a distinct message). Comparing only key
        // names would mis-flag this as VULNERABLE; it must be treated as diverged.
        String toolsCallBody =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\",\"arguments\":{}}}";
        String baselineResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"file-a\\nfile-b\"}],\"isError\":false}}";
        String probeResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"request blocked: host attacker.example not allowed\"}],\"isError\":false}}";
        stubTrackingMcpRequest(toolsCallBody);
        stubBaselineResponse(200, baselineResult, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_HOST)) {
                return httpRequestResponse(200, probeResult, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .extracting(AuditIssue::name)
                .doesNotContain(DNS_REBINDING_ISSUE_NAME);
    }

    @Test
    void flags_dns_rebinding_when_toolcall_probe_replays_identical_content() {
        // Genuine rebind: the rewritten-Host probe returns the EXACT same tool-call
        // result content as the baseline. Must still fire.
        String toolsCallBody =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\",\"arguments\":{}}}";
        String sharedResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"file-a\\nfile-b\"}],\"isError\":false}}";
        stubTrackingMcpRequest(toolsCallBody);
        stubBaselineResponse(200, sharedResult, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_HOST)) {
                return httpRequestResponse(200, sharedResult, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
    }

    @Test
    void flags_dns_rebinding_when_host_rewritten_probe_returns_equivalent_response() {
        String toolsListBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        String toolsListResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"}]}}";
        stubTrackingMcpRequest(toolsListBody);
        stubBaselineResponse(200, toolsListResult, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_HOST)) {
                return httpRequestResponse(200, toolsListResult, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name()).isEqualTo(DNS_REBINDING_ISSUE_NAME);
    }

    @Test
    void flags_dns_rebinding_against_initialize_baseline() {
        String initializeBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
        String initializeResult = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"protocolVersion\":\"2025-11-25\","
                + "\"serverInfo\":{\"name\":\"my-server\",\"version\":\"1.0\"},"
                + "\"capabilities\":{\"tools\":{},\"resources\":{}}}}";
        stubTrackingMcpRequest(initializeBody);
        stubBaselineResponse(200, initializeResult, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_ORIGIN)) {
                return httpRequestResponse(200, initializeResult, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
    }

    @Test
    void does_not_flag_when_probe_response_differs_materially_from_baseline() {
        String toolsListBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        String baselineTools =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"},{\"name\":\"c\"},{\"name\":\"d\"},{\"name\":\"e\"}]}}";
        String filteredTools =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}";
        stubTrackingMcpRequest(toolsListBody);
        stubBaselineResponse(200, baselineTools, "application/json");
        HttpRequestResponse filtered = httpRequestResponse(200, filteredTools, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(filtered);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void does_not_flag_when_probe_returns_4xx() {
        String toolsListBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        String toolsListResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"}]}}";
        stubTrackingMcpRequest(toolsListBody);
        stubBaselineResponse(200, toolsListResult, "application/json");
        HttpRequestResponse forbidden = httpRequestResponse(403, "Forbidden", "text/plain");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(forbidden);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void still_inconclusive_when_baseline_itself_failed() {
        String toolsListBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        stubTrackingMcpRequest(toolsListBody);
        // Baseline server returned a JSON-RPC error — not a successful MCP response.
        stubBaselineResponse(200, JSONRPC_ERROR_BODY, "application/json");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void flags_low_severity_origin_finding_when_no_auth_required_and_probe_matches() {
        String toolsListBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        String toolsListResult =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"public-tool\"}]}}";
        stubTrackingMcpRequest(toolsListBody);
        when(httpService.host()).thenReturn("mcp.example.com");
        stubBaselineResponse(200, toolsListResult, "application/json");
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            if (isProbe(sent, ProbeId.HOSTILE_ORIGIN)) {
                return httpRequestResponse(200, toolsListResult, "application/json");
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo(ORIGIN_VALIDATION_ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void runs_once_per_host_on_per_request_dispatch() {
        stubTrackingMcpToolsCallRequest();
        HttpRequestResponse forbidden = httpRequestResponse(403, "Forbidden", "text/plain");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(forbidden);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        reset(http);
        check.doCheck(baseRequestResponse, insertionPoint, http);

        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void runs_independently_for_distinct_hosts() {
        stubTrackingMcpToolsCallRequest();
        HttpRequestResponse forbidden = httpRequestResponse(403, "Forbidden", "text/plain");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(forbidden);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        // Re-target the same baseline fixture to a different host. Probes must fire again.
        when(httpService.host()).thenReturn("other-host.example");
        check.doCheck(baseRequestResponse, insertionPoint, http);

        // Each invocation issues 4 probes (Origin x3 + Host x1 per PROBES list).
        verify(http, times(8)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void does_not_dedup_when_probe_sequence_had_http_layer_error() {
        stubTrackingMcpToolsCallRequest();
        HttpRequestResponse nullResponse = mock(HttpRequestResponse.class);
        lenient().when(nullResponse.response()).thenReturn(null);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(nullResponse);

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.doCheck(baseRequestResponse, insertionPoint, http);

        verify(http, atLeastOnce()).sendRequest(any(HttpRequest.class));
        verify(http, times(8)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void consolidateIssues_returnsKeepBothForUnrelatedNames() {
        AuditIssue existing = issueWithName(DNS_REBINDING_ISSUE_NAME);
        AuditIssue incoming = issueWithName("Something Else");

        assertThat(check.consolidateIssues(existing, incoming)).isEqualTo(ConsolidationAction.KEEP_BOTH);
    }

    // ---------- Probe identity detection ----------

    private enum ProbeId {
        HOSTILE_ORIGIN, NULL_ORIGIN, ATTACKER_DOMAIN_ORIGIN, HOSTILE_HOST
    }

    private static boolean isProbe(HttpRequest sent, ProbeId probeId) {
        return switch (probeId) {
            case HOSTILE_ORIGIN -> "http://evil.example".equals(sent.headerValue("Origin"));
            case NULL_ORIGIN -> "null".equals(sent.headerValue("Origin"));
            case ATTACKER_DOMAIN_ORIGIN -> "http://attacker.example:1337".equals(sent.headerValue("Origin"));
            case HOSTILE_HOST -> "attacker.example".equals(sent.headerValue("Host"))
                    && "http://attacker.example".equals(sent.headerValue("Origin"));
        };
    }

    // ---------- Tracking-request stub builders ----------

    private void stubTrackingMcpToolsCallRequest() {
        stubTrackingMcpRequest(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\",\"arguments\":{}}}");
    }

    private void stubTrackingMcpRequestWithAuthHeader(String headerName, String headerValue) {
        Map<String, String> seedHeaders = new LinkedHashMap<>();
        seedHeaders.put("Origin", "http://localhost:3000");
        seedHeaders.put(headerName, headerValue);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
        HttpRequest trackingRequest = trackingHttpRequest(httpService, "/mcp", seedHeaders,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\",\"arguments\":{}}}");
        when(baseRequestResponse.request()).thenReturn(trackingRequest);
        stubBaselineResponse(200, JSONRPC_RESULT_BODY, "application/json");
    }

    private void stubTrackingMcpRequest(String body) {
        Map<String, String> seedHeaders = new LinkedHashMap<>();
        seedHeaders.put("Origin", "http://localhost:3000");
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
        HttpRequest trackingRequest = trackingHttpRequest(httpService, "/mcp", seedHeaders, body);
        when(baseRequestResponse.request()).thenReturn(trackingRequest);
        stubBaselineResponse(200, JSONRPC_RESULT_BODY, "application/json");
    }

    private void stubBaselineResponse(int statusCode, String body, String contentType) {
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(baseRequestResponse.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn(contentType);
    }

    private void stubServerRejectingAllProbes() {
        HttpRequestResponse forbidden = httpRequestResponse(403, "Forbidden", "text/plain");
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(forbidden);
    }

    private void stubServerAcceptingOnlyProbe(ProbeId acceptedProbeId) {
        stubServerAcceptingProbes(acceptedProbeId);
    }

    private void stubServerAcceptingProbes(ProbeId... acceptedProbeIds) {
        java.util.Set<ProbeId> accepted = java.util.EnumSet.noneOf(ProbeId.class);
        for (ProbeId id : acceptedProbeIds) {
            accepted.add(id);
        }
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            for (ProbeId id : accepted) {
                if (isProbe(sent, id)) {
                    return httpRequestResponse(200, JSONRPC_RESULT_BODY, "application/json");
                }
            }
            return httpRequestResponse(403, "Forbidden", "text/plain");
        });
    }

    // ---------- Tracking-request factory ----------

    private static HttpRequest trackingHttpRequest(HttpService service, String path,
                                                   Map<String, String> headers, String body) {
        Map<String, String> snapshot = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        snapshot.putAll(headers);
        HttpRequest req = mock(HttpRequest.class);
        List<HttpHeader> headerList = mockHeaderList(snapshot);
        lenient().when(req.method()).thenReturn("POST");
        lenient().when(req.bodyToString()).thenReturn(body);
        lenient().when(req.pathWithoutQuery()).thenReturn(path);
        lenient().when(req.httpService()).thenReturn(service);
        lenient().when(req.headers()).thenReturn(headerList);
        lenient().when(req.headerValue(anyString())).thenAnswer(inv -> headerValueIgnoreCase(snapshot, inv.getArgument(0)));
        lenient().when(req.withRemovedHeaders(anyList())).thenAnswer(inv -> {
            List<HttpHeader> toRemove = inv.getArgument(0);
            Map<String, String> next = new LinkedHashMap<>(snapshot);
            for (HttpHeader h : toRemove) {
                next.keySet().removeIf(existing -> existing.equalsIgnoreCase(h.name()));
            }
            return trackingHttpRequest(service, path, next, body);
        });
        lenient().when(req.withHeader(anyString(), anyString())).thenAnswer(inv -> {
            String name = inv.getArgument(0);
            String value = inv.getArgument(1);
            Map<String, String> next = new LinkedHashMap<>(snapshot);
            next.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
            next.put(name, value);
            return trackingHttpRequest(service, path, next, body);
        });
        return req;
    }

    private static List<HttpHeader> mockHeaderList(Map<String, String> headers) {
        List<HttpHeader> list = new ArrayList<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            HttpHeader h = mock(HttpHeader.class);
            lenient().when(h.name()).thenReturn(entry.getKey());
            lenient().when(h.value()).thenReturn(entry.getValue());
            list.add(h);
        }
        return list;
    }

    private static String headerValueIgnoreCase(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    // ---------- Response builders ----------

    private HttpRequestResponse httpRequestResponse(int statusCode, String body, String contentType) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn(contentType);
        return rr;
    }

    private AuditIssue issueWithName(String name) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        return issue;
    }
}
