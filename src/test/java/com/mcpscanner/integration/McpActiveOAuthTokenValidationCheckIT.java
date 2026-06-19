package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.McpActiveOAuthTokenValidationCheck;
import com.mcpscanner.checks.OAuthJwtProbeFactory;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * E2E integration tests for {@link McpActiveOAuthTokenValidationCheck}.
 *
 * <p>Requires a live test-server process. Gate with {@code MCP_E2E_IT=1}.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveOAuthTokenValidationCheckIT {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void vulnerable_skipSignature_firesIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);

        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-skip-signature")) {

            // Mint an attacker-signed JWT. The server skips signature verification so it
            // will accept any JWT with correct-looking aud/iss claims.
            String issuer = "http://" + McpCheckItSupport.HOST + ":" + server.port();
            String audience = issuer + "/mcp";
            OAuthJwtProbeFactory probeFactory = new OAuthJwtProbeFactory();
            String baselineToken = probeFactory.mintProbes(List.of(audience), Optional.of(issuer))
                    .stream()
                    .filter(p -> OAuthJwtProbeFactory.LABEL_RANDOM_SIG.equals(p.label()))
                    .findFirst()
                    .map(OAuthJwtProbeFactory.JwtProbe::token)
                    .orElseThrow(() -> new IllegalStateException("No RANDOM_SIG probe minted"));

            // Initialize a proper MCP session authenticated with our attacker-signed JWT.
            // This is necessary so the probe tool-calls hit an initialized session and
            // return a proper tools/call result (not a "Missing session ID" 400).
            String sessionId =
                    McpCheckItSupport.initializeSessionWithBearer(server.port(), baselineToken);

            HttpRequestResponse baseline = McpCheckItSupport.buildUserInfoBaseline(
                    server.port(), sessionId, "Bearer " + baselineToken);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            BearerTokenAuthStrategy authStrategy = new BearerTokenAuthStrategy(baselineToken);
            McpActiveOAuthTokenValidationCheck check =
                    new McpActiveOAuthTokenValidationCheck(settings, () -> authStrategy);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("oauth-skip-signature server should fire JWT validation issue")
                    .isNotEmpty();
        }
    }

    @Test
    void safe_realValidJwtAgainstStrictlyValidatingServer_noIssue() throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);

        try (McpCheckItSupport.RunningServer server =
                     McpCheckItSupport.startServer("--auth", "oauth", "--oauth-test-mint-endpoint")) {

            // Mint a real, signer-issued JWT via the test-only mint endpoint. The server
            // signed this with its own JWKS key, so it passes strict signature validation.
            String validToken = McpCheckItSupport.mintTestToken(server.port());

            // Initialize a proper MCP session under the valid bearer so probe tool-calls
            // hit an initialized session — what we want to observe is the server's
            // strict JWT validation rejecting the attacker-signed probe tokens, not a
            // "Missing session ID" 400 short-circuiting the check.
            String sessionId =
                    McpCheckItSupport.initializeSessionWithBearer(server.port(), validToken);

            HttpRequestResponse baseline = McpCheckItSupport.buildUserInfoBaseline(
                    server.port(), sessionId, "Bearer " + validToken);
            RecordingRealHttp realHttp = new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);

            BearerTokenAuthStrategy authStrategy = new BearerTokenAuthStrategy(validToken);
            McpActiveOAuthTokenValidationCheck check =
                    new McpActiveOAuthTokenValidationCheck(settings, () -> authStrategy);

            AuditResult result = check.doCheck(baseline, insertionPoint, realHttp);

            assertThat(result.auditIssues())
                    .as("Strict-validating server should reject every RANDOM_SIG / ALG_NONE / "
                            + "WRONG_AUD / WRONG_ISS / EXPIRED probe — no JWT-validation issue")
                    .isEmpty();
        }
    }

}
