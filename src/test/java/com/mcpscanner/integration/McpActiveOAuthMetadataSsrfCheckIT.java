package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.McpActiveOAuthMetadataSsrfCheck;
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
 * E2E integration tests for {@link McpActiveOAuthMetadataSsrfCheck}.
 *
 * <p>Requires a live test-server process. Gate with {@code MCP_E2E_IT=1}.
 *
 * <p>Vulnerable scenario: the server runs with {@code --auth oauth} and
 * {@code --oauth-issuer-override http://169.254.169.254/iam}. The AS metadata
 * document at {@code /.well-known/oauth-authorization-server} advertises cloud-metadata
 * URLs (169.254.169.254) for {@code issuer}, {@code authorization_endpoint}, etc.
 * The check classifies these as "cloud-metadata" and raises an SSRF issue.
 *
 * <p>Safe scenario: the server runs with no auth ({@code --auth none}, the default).
 * No WWW-Authenticate header is emitted and no OAuth discovery documents are served,
 * so the check finds no suspicious URLs and returns no issues.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveOAuthMetadataSsrfCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void vulnerable_metadataPointsToCloudMetadata_firesIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveOAuthMetadataSsrfCheck check = new McpActiveOAuthMetadataSsrfCheck(settings);

        // The issuer-override flag rewrites AS metadata URLs to point at the cloud metadata
        // endpoint (169.254.169.254). The SSRF check fetches this document and classifies
        // all overridden URLs as "cloud-metadata" → issue fires.
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer(
                "--auth", "oauth",
                "--oauth-issuer-override", "http://169.254.169.254/iam")) {

            String sessionId = McpCheckItSupport.initializeSession(server.port());
            HttpRequestResponse baseline = buildToolsListBaseline(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("OAuth server advertising cloud-metadata issuer URLs should fire SSRF issue")
                    .isNotEmpty();
        }
    }

    @Test
    void safe_noOAuth_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveOAuthMetadataSsrfCheck check = new McpActiveOAuthMetadataSsrfCheck(settings);

        // No-auth server: unauthenticated probe returns 200 (no WWW-Authenticate),
        // well-known endpoints return 404. The check finds no OAuth discovery metadata
        // to inspect and returns no issues.
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer()) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            HttpRequestResponse baseline = buildToolsListBaseline(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("No-auth server with no OAuth discovery documents should not fire SSRF issue")
                    .isEmpty();
        }
    }

    private static HttpRequestResponse buildToolsListBaseline(int port, String sessionId) {
        String endpoint = McpCheckItSupport.mcpEndpoint(port);
        HttpRequest request = HttpRequest.httpRequestFromUrl(endpoint)
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        return HttpRequestResponse.httpRequestResponse(request, null);
    }
}
