package com.mcpscanner.integration;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.McpActiveConsentPageReflectedXssCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.scan.ScanStartContext;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * E2E integration tests for {@link McpActiveConsentPageReflectedXssCheck}.
 *
 * <p>Requires a live test-server process. Gate with {@code MCP_E2E_IT=1}.
 *
 * <p>These cases prove the check detects a reflected-XSS bug CLASS — an OAuth AS echoing the
 * attacker-controlled DCR {@code client_name} into its self-rendered consent page un-encoded in a
 * tag-parsing context — across MANY server shapes, not one vendor's fingerprint. Each
 * {@code --oauth-consent-page} variant is a genuinely different bug shape (sink, bounce style, trust
 * gate); the suite asserts the check fires HIGH/FIRM on every real bug and stays silent on the
 * non-executable comment-only shape.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveConsentPageReflectedXssCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    /**
     * Every variant here interpolates {@code client_name} RAW into a tag-parsing context with no
     * mitigating CSP — a real bug in a distinct shape:
     * <ul>
     *   <li>{@code vulnerable} — raw in a {@code <script>} island, direct 200.</li>
     *   <li>{@code bounce-loopback} — cross-origin login bounce (postSignUp) + raw only for loopback redirect.</li>
     *   <li>{@code body-https} — raw in a plain HTML body element, direct 200, https path.</li>
     *   <li>{@code attribute} — raw inside an href attribute value.</li>
     *   <li>{@code bounce-altparam} — login bounce carrying the consent URL in an alternate param.</li>
     *   <li>{@code inverse-trust} — raw only for the https redirect (inverse of the loopback gate).</li>
     * </ul>
     */
    @ParameterizedTest(name = "consent-page={0} fires HIGH/FIRM")
    @ValueSource(strings = {"vulnerable", "bounce-loopback", "body-https", "attribute", "bounce-altparam", "inverse-trust"})
    void realBugShape_firesHighFirm(String consentPageVariant) throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveConsentPageReflectedXssCheck check = new McpActiveConsentPageReflectedXssCheck(settings);

        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-consent-page", consentPageVariant)) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            ScanStartContext context = sessionContext(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            List<AuditIssue> issues = check.runOnceForSession(context, realHttp);

            assertThat(issues)
                    .as("Raw reflection (%s shape) should fire one reflected-XSS precondition issue",
                            consentPageVariant)
                    .hasSize(1);
            AuditIssue issue = issues.get(0);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }
    }

    /**
     * Variants where the canary survives raw but in a NON-executable position, so the check must
     * raise nothing:
     * <ul>
     *   <li>{@code safe} — client_name is HTML-escaped.</li>
     *   <li>{@code comment-only} — marker survives only inside an HTML comment (never tag-parsed).</li>
     * </ul>
     */
    @ParameterizedTest(name = "consent-page={0} raises no issue")
    @ValueSource(strings = {"safe", "comment-only"})
    void nonExecutableShape_noIssue(String consentPageVariant) throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveConsentPageReflectedXssCheck check = new McpActiveConsentPageReflectedXssCheck(settings);

        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-consent-page", consentPageVariant)) {
            String sessionId = McpCheckItSupport.initializeSession(server.port());
            ScanStartContext context = sessionContext(server.port(), sessionId);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            List<AuditIssue> issues = check.runOnceForSession(context, realHttp);

            assertThat(issues)
                    .as("Non-executable reflection (%s shape) must NOT fire an issue", consentPageVariant)
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
