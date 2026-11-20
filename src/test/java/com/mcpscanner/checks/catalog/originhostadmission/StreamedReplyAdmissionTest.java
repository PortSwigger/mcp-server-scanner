package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.stream.ScriptedEventStreams;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ClosedPort;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.LOOPBACK_URL;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.TOOLS_RESULT;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.captured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.ok;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.toolsList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StreamedReplyAdmissionTest {

    private static final String ORIGIN_ISSUE = "MCP Origin header admission";
    private static final String HOST_ISSUE = "MCP Host header admission";
    private static final String HOST_AND_ORIGIN_ISSUE = "MCP Host and Origin header admission";
    private static final String OUTSIDE_BURP = "with its own HTTP client, outside Burp";

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void judgesOriginAndHostProbesOutsideBurpWhenBurpWithholdsTheStreamedReply() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            List<AuditIssue> issues = check().audit(captured(toolsList(server.url())), server.burp);

            assertThat(issues).extracting(AuditIssue::name)
                    .containsExactly(ORIGIN_ISSUE, HOST_ISSUE, HOST_AND_ORIGIN_ISSUE);
            assertThat(server.receivedOrigins).containsExactly("(none)", "http://evil.example", "null",
                    "http://attacker.example:1337", "(none)", "http://attacker.example", "(none)");
        }
    }

    @Test
    void sendsTheHostProbesForeignHostHeaderToTheServerVerbatim() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            check().audit(captured(toolsList(server.url())), server.burp);

            assertThat(server.receivedHosts).filteredOn("attacker.example"::equals).hasSize(2);
        }
    }

    @Test
    void theHostAndOriginIssueNamesTheHostProbeSentOutsideBurp() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            AuditIssue issue = check().audit(captured(toolsList(server.url())), burpAnsweringOnlyTheFirstRequest())
                    .stream().filter(candidate -> candidate.name().equals(HOST_AND_ORIGIN_ISSUE))
                    .findFirst().orElseThrow();

            assertThat(issue.detail()).contains("The scanner sent the Host: attacker.example + Origin: "
                    + "http://attacker.example probe " + OUTSIDE_BURP);
            assertThat(issue.requestResponses().get(1).response().statusCode()).isEqualTo((short) 200);
        }
    }

    @Test
    void theOriginIssueSaysItsTrafficWentOutsideBurpAndCitesTheProbeExchanges() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            AuditIssue issue = check().audit(captured(toolsList(server.url())), server.burp).get(0);

            assertThat(issue.detail()).contains("The scanner sent these requests " + OUTSIDE_BURP);
            assertThat(issue.requestResponses()).hasSize(2)
                    .allSatisfy(exchange -> assertThat(exchange.response().statusCode()).isEqualTo((short) 200));
            assertThat(issue.requestResponses())
                    .extracting(exchange -> exchange.request().headerValue("Origin"))
                    .containsExactly(null, "http://evil.example");
        }
    }

    @Test
    void theOriginIssueNamesOnlyTheRequestsSentOutsideBurpWhenBurpAnsweredTheBaseline() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            AuditIssue issue = check().audit(captured(toolsList(server.url())), burpAnsweringOnlyTheFirstRequest())
                    .get(0);

            assertThat(issue.detail()).contains("The scanner sent the Origin: http://evil.example probe "
                    + OUTSIDE_BURP).doesNotContain("these requests " + OUTSIDE_BURP).doesNotContain("the baseline request");
            assertThat(server.receivedOrigins).containsExactly("http://evil.example", "null",
                    "http://attacker.example:1337", "(none)", "http://attacker.example", "(none)");
        }
    }

    @Test
    void hostProbesSentOutsideBurpSettleTheTrial() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            assertThat(requestSettlement(server)).isEqualTo(HostSettlement.SETTLED);
        }
    }

    @Test
    void theDecisionJudgesTheHostProbesSentOutsideBurp() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            requestSettlement(server);

            assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                    .filteredOn(message -> message.contains("decision: "))
                    .singleElement().asString()
                    .contains("Host: attacker.example -> ADMITTED");
        }
    }

    @Test
    void aServerThatRefusesForeignOriginsAndHostsOutsideBurpIsSilentAndSettles() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.refusingForeignOriginsAndHosts()) {
            assertThat(check().audit(captured(toolsList(server.url())), server.burp)).isEmpty();
            assertThat(requestSettlement(server)).isEqualTo(HostSettlement.SETTLED);
        }
    }

    @Test
    void anOriginProbeLeftUnansweredOutsideBurpLeavesTheTrialInconclusive() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.droppingOrigin("http://evil.example")) {
            assertThat(requestSettlement(server)).isEqualTo(HostSettlement.INCONCLUSIVE);
        }
    }

    @Test
    void anIssueBurpAnsweredCarriesNoOutsideBurpNote() {
        AdmissionServers.Server answering = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        assertThat(check().audit(captured(toolsList(LOOPBACK_URL)), answering.http))
                .isNotEmpty()
                .noneMatch(issue -> issue.detail().contains(OUTSIDE_BURP));
    }

    @Test
    void aStreamingBaselineTheScannersOwnClientCannotReachSettlesTheTrial() throws IOException {
        HttpRequestResponse base = captured(toolsList(unreachableUrl()));

        assertThat(check().trials().get(0).run(base, StreamingAdmissionServer.burpWithholdingStreams()).settlement())
                .isEqualTo(HostSettlement.SETTLED);
    }

    @Test
    void anUnreachableStreamingBaselineIsReportedStoppedOnceAcrossRepeatedAudits() throws IOException {
        HttpRequestResponse base = captured(toolsList(unreachableUrl()));
        HostAudits audits = new HostAudits(check());
        Http burp = StreamingAdmissionServer.burpWithholdingStreams();

        for (int audit = 0; audit < 3; audit++) {
            audits.audit(base, burp);
        }

        assertThat(streamedReplyStops()).singleElement().asString()
                .contains("at http://127.0.0.1")
                .contains("Burp withholds streamed replies from extensions")
                .contains("could not reach the server");
    }

    @Test
    void aStreamingBaselineWhoseHostHeaderNamesAnotherHostIsProbedOutsideBurp() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            HttpRequestResponse base = captured(toolsList(server.url()).withHeader("Host", "other.example"));

            assertThat(check().trials().get(0).run(base, server.burp).settlement())
                    .isEqualTo(HostSettlement.SETTLED);
            assertThat(server.receivedHosts).first().isEqualTo("other.example");
            assertThat(streamedReplyStops()).isEmpty();
        }
    }

    @Test
    void aStreamingBaselineRefusedOutsideBurpLeavesTheTrialUnprobedWithoutAStopLine() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.refusingEveryRequest()) {
            assertThat(requestSettlement(server)).isEqualTo(HostSettlement.NOT_PROBED);
            assertThat(streamedReplyStops()).isEmpty();
        }
    }

    @Test
    void probesGoThroughBurpAgainAfterDisconnectOnceTheServerStopsStreaming() throws IOException {
        try (StreamingAdmissionServer server = StreamingAdmissionServer.admittingEveryOrigin()) {
            OriginHostAdmissionCheck check = check();
            HttpRequestResponse base = captured(toolsList(server.url()));
            check.audit(base, server.burp);
            doAnswer(invocation -> HttpRequestResponse.httpRequestResponse(invocation.getArgument(0), ok(TOOLS_RESULT)))
                    .when(server.burp).sendRequest(any(HttpRequest.class));

            check.clearConnectionState();
            check.audit(base, server.burp);

            assertThat(server.receivedOrigins).hasSize(7);
        }
    }

    private static Http burpAnsweringOnlyTheFirstRequest() {
        Http burp = mock(Http.class);
        when(burp.sendRequest(any(HttpRequest.class)))
                .thenAnswer(invocation -> HttpRequestResponse.httpRequestResponse(invocation.getArgument(0),
                        ok(TOOLS_RESULT)))
                .thenThrow(new IllegalStateException("Streaming response received"));
        return burp;
    }

    private List<String> streamedReplyStops() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message)
                .filter(message -> message.contains("stopped "))
                .filter(message -> message.contains("(streamed reply withheld by Burp: "))
                .toList();
    }

    private static String unreachableUrl() throws IOException {
        return "http://127.0.0.1:" + ClosedPort.onLoopback() + "/mcp";
    }

    private HostSettlement requestSettlement(StreamingAdmissionServer server) {
        HttpRequestResponse base = captured(toolsList(server.url()));
        return check().trials().get(0).run(base, server.burp).settlement();
    }

    private OriginHostAdmissionCheck check() {
        return new OriginHostAdmissionCheck(eventLog, new CredentialHeaders(NoAuthStrategy::new), Optional::empty,
                ScriptedEventStreams.none(), new ProbeSessions(NoAuthStrategy::new));
    }
}
