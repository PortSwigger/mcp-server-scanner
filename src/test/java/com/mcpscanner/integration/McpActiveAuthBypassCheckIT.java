package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.McpActiveAuthBypassCheck;
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

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveAuthBypassCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void vulnerable_brokenBearer_firesIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        // BearerTokenAuthStrategy so the check sees an auth-bearing header on the baseline
        BearerTokenAuthStrategy authStrategy = new BearerTokenAuthStrategy("test-token");
        McpActiveAuthBypassCheck check = new McpActiveAuthBypassCheck(settings, () -> authStrategy);

        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "broken-bearer")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            // Baseline is a tools/call with a bearer token — check requires auth header present
            HttpRequestResponse baseline =
                    McpCheckItSupport.buildUserInfoBaseline(
                            server.port(), sessionId, "Bearer test-token");
            // Seed the session ID so auth-stripped probes (which strip Mcp-Session-Id) still
            // get a valid session, simulating the SSE proxy's role in production.
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("broken-bearer server should fire auth bypass issue")
                    .isNotEmpty();
        }
    }

    @Test
    void safe_realBearerWithStrictOAuth_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);

        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-test-mint-endpoint")) {

            // Mint a real, signer-issued JWT via the test-only mint endpoint. The server's
            // own signing key produced this token, so it validates cleanly.
            String validToken = McpCheckItSupport.mintTestToken(server.port());

            // Initialize an MCP session under the real bearer so probe tool-calls hit an
            // initialized session and the server's auth enforcement is what we observe
            // (not "Missing session ID" 400s).
            String sessionId =
                    McpCheckItSupport.initializeSessionWithBearer(server.port(), validToken);

            HttpRequestResponse baseline = McpCheckItSupport.buildUserInfoBaseline(
                    server.port(), sessionId, "Bearer " + validToken);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            BearerTokenAuthStrategy authStrategy = new BearerTokenAuthStrategy(validToken);
            McpActiveAuthBypassCheck check =
                    new McpActiveAuthBypassCheck(settings, () -> authStrategy);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("Strict OAuth server should reject every STRIP_AUTH / GARBAGE_BEARER / "
                            + "EMPTY_BEARER / NO_SCHEME probe — no auth-bypass issue")
                    .isEmpty();
        }
    }

}
