package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckRunner;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class OAuthRedirectPolicyCheckIT {

    private static final String CODE_DELIVERY = "MCP OAuth authorization code sent to unregistered redirect URI";
    private static final String ERROR_DELIVERY = "MCP OAuth error response sent to unregistered redirect URI";
    private static final String SCRIPT_SCHEME_REGISTRATION = "MCP OAuth dynamic client registration accepts script-scheme redirect URI";
    private static final String WILDCARD_EXPANSION = "MCP OAuth authorization endpoint expands wildcard redirect URI";
    private static final String ANY_HOST_REGISTRATION =
            "MCP OAuth dynamic client registration accepts redirect URI on any host";

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    static Stream<Arguments> vulnerableModes() {
        return Stream.of(
                Arguments.of("redirect_unregistered", List.of(CODE_DELIVERY, ERROR_DELIVERY),
                        "unregistered path on the registered loopback host"),
                Arguments.of("redirect_http_downgrade", List.of(CODE_DELIVERY), "http downgrade"),
                Arguments.of("redirect_path_normalisation", List.of(CODE_DELIVERY), "dot-segment path"),
                Arguments.of("redirect_script_scheme_registration", List.of(SCRIPT_SCHEME_REGISTRATION),
                        "javascript:void(0)"),
                Arguments.of("redirect_wildcard_registration", List.of(WILDCARD_EXPANSION),
                        "matched only by https://*.client.example.com/"));
    }

    @ParameterizedTest(name = "{0} fires")
    @MethodSource("vulnerableModes")
    void firesOnlyTheFindingsOfTheVulnerableModule(String vulnerability, List<String> expectedIssues,
                                                    String expectedDetail) throws Exception {
        List<AuditIssue> issues = scan("--consent", "auto", "--default-mode", "safe",
                "--vuln", vulnerability + "=vulnerable");

        assertThat(issues).extracting(AuditIssue::name).containsExactlyInAnyOrderElementsOf(
                Stream.concat(expectedIssues.stream(), Stream.of(ANY_HOST_REGISTRATION)).toList());
        assertThat(issues.get(0).detail()).contains(expectedDetail);
    }

    @Test
    void reportsOnlyTheOpenRegistrationPolicyWhenEveryRedirectModuleIsSafe() throws Exception {
        assertThat(scan("--consent", "auto", "--default-mode", "safe")).extracting(AuditIssue::name)
                .containsExactly(ANY_HOST_REGISTRATION);
    }

    @Test
    void reportsNoDeliveryWhenAConsentPageStandsBetweenTheRequestAndTheRedirect() throws Exception {
        List<AuditIssue> issues = scan("--consent", "prompt", "--default-mode", "safe",
                "--vuln", "redirect_unregistered=vulnerable");

        assertThat(issues).extracting(AuditIssue::name).doesNotContain(CODE_DELIVERY);
    }

    private static List<AuditIssue> scan(String... serverArguments) throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer(serverArguments)) {
            McpCheck check = CheckCatalog.discover(CheckServices.standalone()).find("oauth-redirect-policy")
                    .orElseThrow();
            CheckRunner runner = new CheckRunner(new RecordingRealHttp(),
                    new McpInsertionPointProvider()::provideInsertionPoints);
            return new ArrayList<>(runner.run(check, List.of(pingAgainst(server.port()))));
        }
    }

    private static HttpRequestResponse pingAgainst(int port) {
        HttpRequest ping = HttpRequest.httpRequestFromUrl(McpCheckItSupport.mcpEndpoint(port))
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/json")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
        return HttpRequestResponse.httpRequestResponse(ping, null);
    }
}
