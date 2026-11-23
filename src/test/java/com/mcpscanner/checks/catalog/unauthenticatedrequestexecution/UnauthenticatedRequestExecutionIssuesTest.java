package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UnauthenticatedRequestExecutionIssuesTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void rendersNameRatingDetailBackgroundAndEvidence() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(),
                Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN)));
        AuditSubject subject = new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(), true);
        Finding finding = new Finding(FindingKind.AUTHENTICATION_BYPASS, subject, "path.case", "/MCP <x>",
                List.of(baseline, baseline));

        AuditIssue issue = new UnauthenticatedRequestExecutionIssues(List.of("https://ref.example/a")).render(finding);

        assertThat(issue.name()).isEqualTo("MCP authentication bypass");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("tools/call", "path.case = /MCP &lt;x&gt;", "same operation result value",
                "configured with credentials");
        assertThat(issue.remediation()).isEqualTo(FindingKind.AUTHENTICATION_BYPASS.remediation());
        assertThat(issue.requestResponses()).hasSize(2);
    }

    @Test
    void anonymousScanAndNotificationWordingIsHonestAboutWhatWasObserved() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.notification(),
                Map.of()));
        AuditSubject subject = new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(), false);

        AuditIssue issue = new UnauthenticatedRequestExecutionIssues(List.of()).render(new Finding(FindingKind.AUTHENTICATION_BYPASS, subject,
                "path.case", "", List.of(baseline)));

        assertThat(issue.detail()).contains("without credentials", "effect itself is not observed")
                .doesNotContain(" = ");
    }

    @Test
    void forwardedClientWordingClaimsOnlyThatTheGateTrustsTheHeader() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(),
                Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN)));
        AuditSubject subject = new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(), true);

        AuditIssue issue = new UnauthenticatedRequestExecutionIssues(List.of()).render(new Finding(
                FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED, subject, "forwarded-for", "127.0.0.1",
                List.of(baseline)));

        assertThat(issue.name()).isEqualTo("MCP source-address restriction trusts a client-supplied header");
        assertThat(issue.detail()).contains("forwarded-for = 127.0.0.1");
        assertThat(issue.definition().background()).contains("203.0.113.7", "127.0.0.1", "still required",
                "does not show which addresses");
        assertThat(issue.definition().background())
                .contains("depends on a header the client controls",
                        "own address, which the server allows",
                        "does not show that the header replaces the connection",
                        "server errors and proxy errors do not count")
                .doesNotContain("decides who may call it from an address the client supplies");
    }

    @Test
    void forwardedClientBackgroundSaysTheRepeatedRefusalIsSentButNotAttached() {
        assertThat(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED.background())
                .contains("then refused 203.0.113.7 once more",
                        "that repeat is not attached: the evidence holds the baseline request, the first refusal "
                                + "and the admitted request");
    }

    @Test
    void invalidCredentialBackgroundSaysTheSecondFabricatedValueIsTriedButNotAttached() {
        assertThat(FindingKind.INVALID_CREDENTIAL_ACCEPTED.background())
                .contains("again with a second, different fabricated value",
                        "The evidence holds the baseline request, the refusal without a credential and the result "
                                + "for the first fabricated value; the second value's request is not attached.");
    }
}
