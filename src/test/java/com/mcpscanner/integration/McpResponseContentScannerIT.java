package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.JsonRpcResponseContentScanner;
import com.mcpscanner.checks.content.ContentFindingIssueBuilder;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
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

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpResponseContentScannerIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Test
    void leakyToolOutput_firesResponseContentIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        JsonRpcResponseContentScanner scanner =
                new JsonRpcResponseContentScanner(settings, (McpEventLog) null);

        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer(
                "--enable", "deploy_status", "--auth", "none")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            HttpRequestResponse pair = callTool(server.port(), sessionId, "deploy_status");

            AuditResult result = scanner.doCheck(pair);

            assertThat(result.auditIssues())
                    .as("deploy_status leaks a real-looking AWS key in its runtime output")
                    .extracting(AuditIssue::name)
                    .contains(new AwsAccessKeyRule().displayName()
                            + ContentFindingIssueBuilder.RESPONSE_SOURCE.nameQualifier());
        }
    }

    @Test
    void cleanToolOutput_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        JsonRpcResponseContentScanner scanner =
                new JsonRpcResponseContentScanner(settings, (McpEventLog) null);

        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer(
                "--enable", "user_info", "--auth", "none")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            HttpRequestResponse pair = callUserInfo(server.port(), sessionId);

            AuditResult result = scanner.doCheck(pair);

            assertThat(result.auditIssues())
                    .as("user_info returns no high-precision secret in its output")
                    .isEmpty();
        }
    }

    private static HttpRequestResponse callTool(int port, String sessionId, String toolName) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(McpCheckItSupport.mcpEndpoint(port))
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"" + toolName + "\",\"arguments\":{}}}")
                .withAddedHeader("Content-Type", "application/json")
                .withAddedHeader("Accept", "application/json, text/event-stream");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        return new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId).sendRequest(request);
    }

    private static HttpRequestResponse callUserInfo(int port, String sessionId) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(McpCheckItSupport.mcpEndpoint(port))
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"user_info\",\"arguments\":{\"username\":\"alice\"}}}")
                .withAddedHeader("Content-Type", "application/json")
                .withAddedHeader("Accept", "application/json, text/event-stream");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        return new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId).sendRequest(request);
    }
}
