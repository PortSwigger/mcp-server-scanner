package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.stream.EventStreams;
import com.mcpscanner.checks.shared.stream.ScriptedEventStreams;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.LOOPBACK_URL;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.admitting;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.captured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.hostIsCaptured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.noForeignOrigin;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class StreamAdmissionTest {

    private static final String STREAM_ISSUE = "MCP event stream Origin header admission";
    private static final String OWN_ORIGIN = "http://127.0.0.1:8765";

    private final AdmissionServers.Server guardedPosts =
            new AdmissionServers.Server(admitting(hostIsCaptured().and(noForeignOrigin())));

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void aStreamThatOpensForForeignOriginsBehindGuardedPostsIsReported() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> true);

        List<AuditIssue> issues = check(streams).audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);

        AuditIssue stream = issues.stream().filter(issue -> issue.name().equals(STREAM_ISSUE)).findFirst()
                .orElseThrow();
        assertThat(issues).extracting(AuditIssue::name).containsExactly(STREAM_ISSUE);
        assertThat(stream.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(stream.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(stream.detail()).contains("Origin: http://evil.example", "Origin: null", "event stream",
                "outside Burp", "final control", "the first admitted foreign opening are attached");
        assertThat(stream.requestResponses()).extracting(exchange -> exchange.request().headerValue("Origin"))
                .containsExactly(OWN_ORIGIN, "http://evil.example");
    }

    @Test
    void probesTheStreamWithASameOriginControlBeforeAndAfterTheForeignOrigins() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> true);

        check(streams).audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);

        assertThat(streams.opened).extracting(request -> request.headerValue("Origin")).containsExactly(
                OWN_ORIGIN, "http://evil.example", "null", "http://attacker.example:1337", OWN_ORIGIN);
        assertThat(streams.opened).allSatisfy(request -> {
            assertThat(request.method()).isEqualTo("GET");
            assertThat(request.headerValue("Accept")).isEqualTo("text/event-stream");
            assertThat(request.headerValue("Authorization")).isEqualTo("Bearer live");
        });
    }

    @Test
    void aStreamThatRefusesForeignOriginsIsSilent() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(sameOriginOnly());

        assertThat(check(streams).audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http)).isEmpty();
        assertThat(streams.opened).hasSize(5);
    }

    @Test
    void aServerWithoutAnEventStreamIsSilentAfterTheControl() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> false);

        assertThat(check(streams).audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http)).isEmpty();
        assertThat(streams.opened).hasSize(1);
    }

    @Test
    void aHostWhoseStreamNeverOpensIsNotProbedAgain() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> false);
        HostAudits check = new HostAudits(check(streams));

        check.audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);
        check.audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);

        assertThat(streams.opened).hasSize(1);
    }

    @Test
    void aFinalControlThatNoLongerOpensIsSilent() {
        int[] opens = {0};
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> ++opens[0] < 5);

        assertThat(check(streams).audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http)).isEmpty();
    }

    @Test
    void probesEachHostsStreamOnce() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> true);
        HostAudits check = new HostAudits(check(streams));

        check.audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);
        check.audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);

        assertThat(streams.opened).hasSize(5);
    }

    @Test
    void neverProbesTheStreamOnTheSseTransport() {
        ScriptedEventStreams streams = ScriptedEventStreams.inSessions(request -> true);
        OriginHostAdmissionCheck check = new OriginHostAdmissionCheck(McpEventLog.noop(), credentials(),
                () -> Optional.of(HttpService.httpService("127.0.0.1", 40000, false)), streams,
                new ProbeSessions(NoAuthStrategy::new));

        check.audit(captured(toolsList(LOOPBACK_URL)), guardedPosts.http);

        assertThat(streams.opened).isEmpty();
    }

    @Test
    void aConclusiveStreamTrialSettles() {
        assertThat(streamSettlement(ScriptedEventStreams.inSessions(sameOriginOnly())))
                .isEqualTo(HostSettlement.SETTLED);
    }

    @Test
    void aServerWithoutAnEventStreamSettlesTheStreamTrial() {
        assertThat(streamSettlement(ScriptedEventStreams.inSessions(request -> false)))
                .isEqualTo(HostSettlement.SETTLED);
    }

    @Test
    void anUnansweredStreamControlSettlesTheStreamTrial() {
        assertThat(streamSettlement(ScriptedEventStreams.none())).isEqualTo(HostSettlement.SETTLED);
    }

    @Test
    void aFinalControlThatNoLongerOpensLeavesTheStreamTrialInconclusive() {
        int[] opens = {0};

        assertThat(streamSettlement(ScriptedEventStreams.inSessions(request -> ++opens[0] < 5)))
                .isEqualTo(HostSettlement.INCONCLUSIVE);
    }

    @Test
    void theStreamTrialNeverAppliesOnTheSseTransport() {
        OriginHostAdmissionCheck check = new OriginHostAdmissionCheck(McpEventLog.noop(), credentials(),
                () -> Optional.of(HttpService.httpService("127.0.0.1", 40000, false)),
                ScriptedEventStreams.inSessions(request -> true), new ProbeSessions(NoAuthStrategy::new));

        assertThat(check.trials().get(1).appliesTo(captured(toolsList(LOOPBACK_URL)))).isFalse();
    }

    private HostSettlement streamSettlement(EventStreams streams) {
        return check(streams).trials().get(1).run(captured(toolsList(LOOPBACK_URL)), guardedPosts.http).settlement();
    }

    private static Predicate<HttpRequest> sameOriginOnly() {
        return request -> OWN_ORIGIN.equals(request.headerValue("Origin"));
    }

    private static OriginHostAdmissionCheck check(EventStreams streams) {
        return new OriginHostAdmissionCheck(McpEventLog.noop(), credentials(), Optional::empty, streams,
                new ProbeSessions(NoAuthStrategy::new));
    }

    private static CredentialHeaders credentials() {
        return new CredentialHeaders(() -> new BearerTokenAuthStrategy("live"));
    }
}
