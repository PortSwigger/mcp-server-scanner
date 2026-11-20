package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.shared.stream.EventStreams;
import com.mcpscanner.checks.shared.stream.ScriptedEventStreams;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.OwnedLoopbackPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.LOOPBACK_URL;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.TOOLS_RESULT;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.captured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.ok;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.seed;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.status;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class OriginHostAdmissionSkipLogTest {

    private static final String PREFIX = "Scan check: origin-host-admission — ";
    private static final String SUBJECT = "tools/list at " + LOOPBACK_URL;
    private static final String REQUEST_TEST = "the Origin/Host request test on " + SUBJECT;
    private static final String STREAM_TEST = "the GET event-stream test on " + SUBJECT;
    private static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"echo\",\"arguments\":{}}}";

    private final McpEventLog eventLog = new McpEventLog(null);
    private final AdmissionServers.Server open = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void logsWhyARequestThatIsNotSafeToReplayIsSkipped() {
        audits(ScriptedEventStreams.none()).audit(captured(seed(LOOPBACK_URL, TOOL_CALL)), open.http);

        assertThat(messages()).containsExactly(PREFIX + "skipped tools/call echo at " + LOOPBACK_URL
                + " (not applicable: replays only read-only listings, reads and prompt gets)");
    }

    @Test
    void logsThatAHostAlreadyProbedIsSkipped() {
        HostAudits check = audits(ScriptedEventStreams.inSessions(request -> false));
        check.audit(captured(toolsList(LOOPBACK_URL)), open.http);

        check.audit(captured(toolsList(LOOPBACK_URL)), open.http);

        assertThat(messages()).contains(
                PREFIX + "skipped " + REQUEST_TEST + " (already audited on this connection: this host was already probed)",
                PREFIX + "skipped " + STREAM_TEST + " (already audited on this connection: this host was already probed)");
    }

    @Test
    void logsThatAHostOutOfAttemptsIsSkipped() {
        int[] calls = {0};
        AdmissionServers.Server flaky = new AdmissionServers.Server(request ->
                ++calls[0] % 7 == 0 ? status(500, "") : ok(TOOLS_RESULT));
        HostAudits check = audits(ScriptedEventStreams.none());

        for (int attempt = 0; attempt <= HostAudits.MAX_INCONCLUSIVE_ATTEMPTS; attempt++) {
            check.audit(captured(toolsList(LOOPBACK_URL)), flaky.http);
        }

        assertThat(messages()).contains(PREFIX + "stopped " + REQUEST_TEST + " (request budget used up: "
                + HostAudits.MAX_INCONCLUSIVE_ATTEMPTS + " inconclusive attempts on this host)");
    }

    @Test
    void logsThatARateLimitedBaselineStopsTheRequestTest() {
        AdmissionServers.Server limiting = new AdmissionServers.Server(request -> status(429, ""));

        check(ScriptedEventStreams.none()).audit(captured(toolsList(LOOPBACK_URL)), limiting.http);

        assertThat(messages()).contains(PREFIX + "stopped " + REQUEST_TEST
                + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void logsThatAFailingBaselineStopsTheRequestTest() {
        AdmissionServers.Server failing = new AdmissionServers.Server(request -> status(500, ""));

        check(ScriptedEventStreams.none()).audit(captured(toolsList(LOOPBACK_URL)), failing.http);

        assertThat(messages()).contains(PREFIX + "skipped " + REQUEST_TEST + " (prerequisite missing: the replayed "
                + "request returned no successful result to compare the probes with)");
    }

    @Test
    void logsThatAStreamedReplyStopsTheRequestTest() throws Exception {
        AdmissionServers.Server streaming = new AdmissionServers.Server(request -> {
            throw new IllegalStateException("Streaming response received");
        });

        try (OwnedLoopbackPort target = OwnedLoopbackPort.closingEveryConnection()) {
            String url = target.url("/mcp");
            check(ScriptedEventStreams.none()).audit(captured(toolsList(url)), streaming.http);

            assertThat(messages()).anySatisfy(message -> assertThat(message)
                    .startsWith(PREFIX + "stopped the Origin/Host request test on tools/list at " + url
                            + " (streamed reply withheld by Burp: ")
                    .contains("text/event-stream"));
        }
    }

    @Test
    void logsThatTheStreamTestDoesNotRunOnTheSseTransport() {
        audits(new OriginHostAdmissionCheck(eventLog, credentials(),
                () -> Optional.of(HttpService.httpService("127.0.0.1", 40000, false)),
                ScriptedEventStreams.inSessions(request -> true), new ProbeSessions(NoAuthStrategy::new)))
                .audit(captured(toolsList(LOOPBACK_URL)), open.http);

        assertThat(messages()).contains(PREFIX + "skipped " + STREAM_TEST
                + " (not applicable: the legacy SSE transport has no GET event stream)");
    }

    @Test
    void logsThatTheStreamTestSkipsALegacySseMessageEndpoint() {
        check(ScriptedEventStreams.none()).audit(captured(toolsList(LOOPBACK_URL)), open.http);

        assertThat(messages()).contains(PREFIX + "skipped " + STREAM_TEST
                + " (not applicable: the URL is a legacy SSE message endpoint)");
    }

    @Test
    void logsThatAServerWithoutAnEventStreamStopsTheStreamTest() {
        check(ScriptedEventStreams.inSessions(request -> false)).audit(captured(toolsList(LOOPBACK_URL)), open.http);

        assertThat(messages()).contains(PREFIX + "skipped " + STREAM_TEST
                + " (not applicable: the same-origin control stream did not open)");
    }

    @Test
    void logsThatARateLimitedControlStreamStopsTheStreamTest() {
        check(ScriptedEventStreams.answeringWith(429, false)).audit(captured(toolsList(LOOPBACK_URL)), open.http);

        assertThat(messages()).contains(PREFIX + "stopped " + STREAM_TEST
                + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void logsThatAnUnansweredControlStreamStopsTheStreamTest() {
        check(ScriptedEventStreams.unanswered()).audit(captured(toolsList(LOOPBACK_URL)), open.http);

        assertThat(messages()).contains(PREFIX + "stopped " + STREAM_TEST
                + " (transport failure: the same-origin control stream got no response)");
    }

    private HostAudits audits(EventStreams streams) {
        return audits(check(streams));
    }

    private HostAudits audits(OriginHostAdmissionCheck check) {
        return new HostAudits(check, new CheckLog(eventLog, check.descriptor().id()));
    }

    private OriginHostAdmissionCheck check(EventStreams streams) {
        return new OriginHostAdmissionCheck(eventLog, credentials(), Optional::empty, streams,
                new ProbeSessions(NoAuthStrategy::new));
    }

    private static CredentialHeaders credentials() {
        return new CredentialHeaders(NoAuthStrategy::new);
    }

    private List<String> messages() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
