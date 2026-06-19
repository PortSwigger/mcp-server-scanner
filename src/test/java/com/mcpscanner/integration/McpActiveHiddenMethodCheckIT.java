package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.McpActiveHiddenMethodCheck;
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
 * E2E integration tests for {@link McpActiveHiddenMethodCheck}.
 *
 * <p>Requires a live test-server process. Gate with {@code MCP_E2E_IT=1}.
 *
 * <p>Vulnerable scenario: the server runs with the default {@code --hidden-methods enabled}
 * flag, meaning {@code HiddenMethodsMiddleware} intercepts non-standard methods like
 * {@code debug/info} and {@code admin.config} and returns successful JSON-RPC responses,
 * which the check classifies as SUSPICIOUS.
 *
 * <p>Safe scenario: the server runs with {@code --hidden-methods disabled}, meaning
 * {@code StrictMethodMiddleware} rejects any non-standard method with -32601 (Method
 * not found), which the check classifies as BORING — no issue fires.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveHiddenMethodCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void vulnerable_hiddenMethodsEnabled_firesIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveHiddenMethodCheck check = new McpActiveHiddenMethodCheck(settings);

        // Default server: HiddenMethodsMiddleware active, responds with success for
        // debug/info and admin.config → classified as SUSPICIOUS → issue fires.
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer()) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            // The check only probes once the baseline is a confirmed successful MCP response,
            // so send a real tools/list and capture the request+response pair as the baseline.
            HttpRequestResponse baseline =
                    realHttp.sendRequest(buildToolsListRequest(server.port(), sessionId));

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("hidden-methods-enabled server should fire MCP Hidden Method Exposed issue")
                    .isNotEmpty();
        }
    }

    @Test
    void safe_hiddenMethodsDisabled_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveHiddenMethodCheck check = new McpActiveHiddenMethodCheck(settings);

        // Strict server: StrictMethodMiddleware returns -32601 for all non-standard methods
        // → classified as BORING → no issue fires.
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--hidden-methods", "disabled")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            HttpRequestResponse baseline =
                    realHttp.sendRequest(buildToolsListRequest(server.port(), sessionId));

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("hidden-methods-disabled server should not fire issue (-32601 for all probes)")
                    .isEmpty();
        }
    }

    private static HttpRequest buildToolsListRequest(int port, String sessionId) {
        String endpoint = McpCheckItSupport.mcpEndpoint(port);
        HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint)
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        return request;
    }
}
