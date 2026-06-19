package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.McpActiveDnsRebindingCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * E2E integration tests for {@link McpActiveDnsRebindingCheck}.
 *
 * <p>Requires a live test-server process. Gate with {@code MCP_E2E_IT=1}.
 *
 * <p>The check requires a successful MCP response in the baseline
 * ({@code isMcpResponseSuccess}) before it runs probes. The baseline must therefore
 * carry an actual response, not {@code null}. We obtain it by running the tools/call
 * request through the Http double before handing it to the check.
 *
 * <p>Two Http doubles back these tests:
 * <ul>
 *   <li>{@link RecordingRealHttp} (JDK {@link java.net.http.HttpClient}) for the
 *       {@code ORIGIN_OVERRIDE} cases. It cannot send an attacker-controlled {@code Host}
 *       header (the client manages Host itself), so it cannot reach the {@code HOST_OVERRIDE}
 *       branch.</li>
 *   <li>{@link RawSocketHttp} (raw TCP) for the {@code HOST_OVERRIDE} cases. It writes the
 *       spoofed {@code Host} verbatim on the wire and lifts the JSON-RPC reply out of the SSE
 *       frame, mirroring the production SSE proxy — so the DNS-rebinding finding is exercised
 *       end-to-end.</li>
 * </ul>
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveDnsRebindingCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void vulnerable_transportSecurityDisabled_firesIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDnsRebindingCheck check = new McpActiveDnsRebindingCheck(settings);

        // --transport-security disabled (default) means the server does not validate
        // Host or Origin headers → DNS rebinding check should fire.
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--transport-security", "disabled")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            // The check requires a successful MCP response in the baseline.
            // Send a real tools/call and capture the full request+response pair.
            HttpRequest request = buildToolsCallRequest(server.port(), sessionId);
            HttpRequestResponse baseline = realHttp.sendRequest(request);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("transport-security=disabled server should fire DNS rebinding issue")
                    .isNotEmpty();
        }
    }

    @Test
    void safe_transportSecurityEnabled_noOriginIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDnsRebindingCheck check = new McpActiveDnsRebindingCheck(settings);

        // --transport-security enabled means the server rejects requests with hostile Origin
        // headers (403). The ORIGIN_OVERRIDE probes should be classified SECURE (403 in
        // SECURE_STATUS_CODES), so no MCP Origin validation issue should fire.
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--transport-security", "enabled")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            HttpRequest request = buildToolsCallRequest(server.port(), sessionId);
            HttpRequestResponse baseline = realHttp.sendRequest(request);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("transport-security=enabled server should not fire MCP Origin Header "
                            + "Validation issue (server correctly blocks hostile Origin)")
                    .noneMatch(issue -> "MCP Origin Header Validation".equals(issue.name()));
        }
    }

    @Test
    void vulnerable_hostOverride_firesDnsRebindingIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDnsRebindingCheck check = new McpActiveDnsRebindingCheck(settings);

        // --transport-security disabled: the server accepts a spoofed Host header (verified on the
        // wire — see RawSocketHttp). RawSocketHttp writes the attacker-controlled Host verbatim, so
        // the HOST_OVERRIDE probe actually reaches an unprotected server and the DNS-rebinding
        // finding fires. The baseline carries no credentials and the target is loopback, so the
        // check rates this MEDIUM (no credential de-rating to LOW applies).
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--transport-security", "disabled")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            RawSocketHttp rawHttp = new RawSocketHttp(McpCheckItSupport.HOST, server.port());

            HttpRequest request = buildToolsCallRequest(server.port(), sessionId);
            HttpRequestResponse baseline = rawHttp.sendRequest(request);

            AuditResult result = check.doCheck(baseline, insertionPoint, rawHttp);

            AuditIssue dnsRebinding = result.auditIssues().stream()
                    .filter(issue -> "MCP DNS Rebinding".equals(issue.name()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError(
                            "expected an MCP DNS Rebinding issue; got "
                                    + result.auditIssues().stream().map(AuditIssue::name).toList()));

            assertThat(dnsRebinding.severity())
                    .as("loopback target, no baseline credentials → MEDIUM")
                    .isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(dnsRebinding.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }
    }

    @Test
    void safe_hostOverride_validatingServer_noDnsRebindingIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDnsRebindingCheck check = new McpActiveDnsRebindingCheck(settings);

        // --transport-security enabled: the server returns 421 Misdirected Request to a spoofed
        // Host (in SECURE_STATUS_CODES → classified SECURE), so no DNS-rebinding issue must fire.
        // This is the no-false-positive baseline for the HOST_OVERRIDE branch, driven through the
        // same raw-socket double that proves the vulnerable case.
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--transport-security", "enabled")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            RawSocketHttp rawHttp = new RawSocketHttp(McpCheckItSupport.HOST, server.port());

            HttpRequest request = buildToolsCallRequest(server.port(), sessionId);
            HttpRequestResponse baseline = rawHttp.sendRequest(request);

            AuditResult result = check.doCheck(baseline, insertionPoint, rawHttp);

            assertThat(result.auditIssues())
                    .as("transport-security=enabled server rejects spoofed Host (421) → no finding")
                    .noneMatch(issue -> "MCP DNS Rebinding".equals(issue.name()));
        }
    }

    private static HttpRequest buildToolsCallRequest(int port, String sessionId) {
        String endpoint = McpCheckItSupport.mcpEndpoint(port);
        HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint)
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"user_info\",\"arguments\":{\"username\":\"alice\"}}}");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        return request;
    }
}
