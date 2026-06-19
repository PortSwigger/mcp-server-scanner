package com.mcpscanner.integration;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.McpActiveDcrMisconfigurationCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.scan.ScanStartContext;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * E2E integration tests for {@link McpActiveDcrMisconfigurationCheck}.
 *
 * <p>Requires a live test-server process. Gate with {@code MCP_E2E_IT=1}.
 *
 * <p>The check discovers the OAuth AS metadata via the well-known endpoint,
 * then probes the {@code registration_endpoint} for open (unauthenticated) DCR
 * with unsafe redirect_uris.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveDcrMisconfigurationCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Test
    void vulnerable_dcrOpen_firesIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDcrMisconfigurationCheck check = new McpActiveDcrMisconfigurationCheck(settings);

        // --auth oauth with default DCR (no --oauth-dcr-strict) means /register is open —
        // any redirect_uri is accepted. The check should discover the AS metadata via
        // /.well-known/oauth-authorization-server and fire an issue.
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer("--auth", "oauth")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            ScanStartContext context = sessionContext(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            List<AuditIssue> issues = check.runOnceForSession(context, realHttp);

            assertThat(issues)
                    .as("Open DCR server should fire DCR misconfiguration issue")
                    .isNotEmpty();
        }
    }

    @Test
    void echoedButRejectedAtAuthorize_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDcrMisconfigurationCheck check = new McpActiveDcrMisconfigurationCheck(settings);

        // Hardened-but-permissive AS: /register is open and ECHOES the hostile redirect_uri
        // (legal RFC 7591 storage), but GET /authorize REJECTS it (400 invalid_redirect_uri).
        // This is the registration-echo failure mode the Phase-C confirmation must suppress.
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-authorize-reject-unsafe")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            ScanStartContext context = sessionContext(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            List<AuditIssue> issues = check.runOnceForSession(context, realHttp);

            assertThat(issues)
                    .as("AS that echoes at /register but rejects at /authorize must NOT fire an issue")
                    .isEmpty();
        }
    }

    @Test
    void safe_dcrStrict_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveDcrMisconfigurationCheck check = new McpActiveDcrMisconfigurationCheck(settings);

        // --oauth-dcr-strict requires a Bearer token on /register and validates redirect_uris.
        // The check's unauthenticated registration attempt should be rejected (401/403).
        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-dcr-strict")) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            ScanStartContext context = sessionContext(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            List<AuditIssue> issues = check.runOnceForSession(context, realHttp);

            assertThat(issues)
                    .as("DCR-strict server should not fire DCR misconfiguration issue")
                    .isEmpty();
        }
    }

    private static ScanStartContext sessionContext(int port, String sessionId) {
        Map<String, String> headers = sessionId != null
                ? Map.of("Mcp-Session-Id", sessionId)
                : Map.of();
        return new ScanStartContext(McpCheckItSupport.mcpEndpoint(port), headers);
    }
}
