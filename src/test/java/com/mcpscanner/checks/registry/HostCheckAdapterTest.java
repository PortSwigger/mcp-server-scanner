package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.RecordingChecks;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.ConnectionReusingHttp;
import com.mcpscanner.http.OutsideScanQueue;
import com.mcpscanner.http.ScanQueueBypass;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HostCheckAdapterTest {

    private final AuditIssue issue = mock(AuditIssue.class);
    private final Http http = mock(Http.class);
    private final HttpRequestResponse firstOnHostA = AdapterFixtures.baseOn("a.test");
    private final HttpRequestResponse secondOnHostA = AdapterFixtures.baseOn("A.test");
    private final HttpRequestResponse onHostB = AdapterFixtures.baseOn("b.test");

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void registersWithBurpPerRequestSoHostAuditsDecidesWhenAHostIsDone() {
        assertThat(AdapterFixtures.registeredScanCheckType(adapterFor(new RecordingChecks.Host("h", List.of()), true)))
                .isEqualTo(ScanCheckType.PER_REQUEST);
    }

    @Test
    void auditsEachHostOnlyOncePerSession() {
        RecordingChecks.Host check = new RecordingChecks.Host("h", List.of(issue));
        HostCheckAdapter adapter = adapterFor(check, true);

        List<AuditIssue> first = adapter.doCheck(firstOnHostA, null, http).auditIssues();
        List<AuditIssue> repeat = adapter.doCheck(secondOnHostA, null, http).auditIssues();
        List<AuditIssue> other = adapter.doCheck(onHostB, null, http).auditIssues();

        assertThat(first).containsExactly(issue);
        assertThat(repeat).isEmpty();
        assertThat(other).containsExactly(issue);
        assertThat(check.calls).extracting(RecordingChecks.Call::base).containsExactly(firstOnHostA, onHostB);
    }

    @Test
    void clearingSessionStateAllowsTheHostToBeAuditedAgain() {
        RecordingChecks.Host check = new RecordingChecks.Host("h", List.of(issue));
        HostCheckAdapter adapter = adapterFor(check, true);
        adapter.doCheck(firstOnHostA, null, http);

        adapter.clearConnectionState();

        assertThat(adapter.doCheck(firstOnHostA, null, http).auditIssues()).containsExactly(issue);
        assertThat(check.calls).hasSize(2);
    }

    @Test
    void disabledCheckNeitherRunsNorClaimsTheHost() {
        RecordingChecks.Host check = new RecordingChecks.Host("h", List.of(issue));
        ScanCheckSettings settings = AdapterFixtures.settingsAllowing(false);
        HostCheckAdapter adapter = new HostCheckAdapter(settings, McpEventLog.noop(), check);

        assertThat(adapter.doCheck(firstOnHostA, null, http).auditIssues()).isEmpty();
        assertThat(check.calls).isEmpty();
    }

    @Test
    void aFailedAuditReleasesTheHostSoALaterScanRetriesIt() {
        FlakyHostCheck check = new FlakyHostCheck(issue);
        HostCheckAdapter adapter = new HostCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(), check);

        assertThatThrownBy(() -> adapter.doCheck(firstOnHostA, null, http)).isInstanceOf(IllegalStateException.class);

        assertThat(adapter.doCheck(firstOnHostA, null, http).auditIssues()).containsExactly(issue);
        assertThat(check.attempts.get()).isEqualTo(2);
    }

    @Test
    void aBaseRequestTheCheckDoesNotApplyToLeavesTheHostUnclaimed() {
        HttpRequestResponse applicable = AdapterFixtures.baseOn("a.test");
        RecordingChecks.Host check = new RecordingChecks.Host("h", List.of(issue), base -> base == applicable);
        HostCheckAdapter adapter = adapterFor(check, true);

        List<AuditIssue> skipped = adapter.doCheck(firstOnHostA, null, http).auditIssues();
        List<AuditIssue> audited = adapter.doCheck(applicable, null, http).auditIssues();

        assertThat(skipped).isEmpty();
        assertThat(audited).containsExactly(issue);
        assertThat(check.calls).extracting(RecordingChecks.Call::base).containsExactly(applicable);
    }

    @Test
    void logsWhyAHostIsSkipped() {
        McpEventLog eventLog = new McpEventLog(null);
        RecordingChecks.Host check = new RecordingChecks.Host("h", List.of(), base -> base != onHostB);
        HostCheckAdapter adapter = new HostCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog, check);

        adapter.doCheck(firstOnHostA, null, http);
        adapter.doCheck(secondOnHostA, null, http);
        adapter.doCheck(onHostB, null, http);

        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message).contains(
                "Scan check: h — skipped a base request without a request "
                        + "(already audited on this connection: this host was already probed)",
                "Scan check: h — skipped a base request without a request "
                        + "(not applicable: applies only to recorded requests)");
    }

    @Test
    void rejectsACheckWhoseDescriptorDeclaresAnotherKind() {
        RecordingChecks.Host mislabelled = new RecordingChecks.Host(
                RecordingChecks.descriptorFor("h", CheckKind.REQUEST), List.of());

        assertThatThrownBy(() -> adapterFor(mislabelled, true)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aSendTheCheckMarksOutsideTheScanQueueLeavesBurpsAuditHttpForTheUnqueuedHttp() {
        Http unqueued = mock(Http.class);
        HttpRequest oauth = HttpRequest.httpRequestFromUrl("https://a.test/register");
        HttpRequest mcp = HttpRequest.httpRequestFromUrl("https://a.test/mcp");
        HostCheckAdapter adapter = new HostCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(),
                new SendingHostCheck(http -> {
                    OutsideScanQueue.send(http, oauth);
                    http.sendRequest(mcp);
                }), CheckInstrumentation.NONE, UpstreamExchanges.NONE, ConnectionReuse.withoutLocalAnswers(),
                IssueDestination.NONE, new ScanNotices(), ProbeCalls.NONE, ScanQueueBypass.through(unqueued));

        adapter.doCheck(firstOnHostA, null, http);

        verify(unqueued).sendRequest(argThat((HttpRequest sent) -> sent.url().equals(oauth.url())));
        verify(http).sendRequest(argThat((HttpRequest sent) -> sent.url().equals(mcp.url())));
        verify(http, never()).sendRequest(argThat((HttpRequest sent) -> sent.url().equals(oauth.url())));
    }

    @Test
    void anHttpAlreadyOffTheScanQueueKeepsTheChecksMarkedSends() {
        Http unqueued = mock(Http.class);
        HttpRequest oauth = HttpRequest.httpRequestFromUrl("https://a.test/register");
        HostCheckAdapter adapter = new HostCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(),
                new SendingHostCheck(http -> OutsideScanQueue.send(http, oauth)), CheckInstrumentation.NONE,
                UpstreamExchanges.NONE, ConnectionReuse.withoutLocalAnswers(), IssueDestination.NONE,
                new ScanNotices(), ProbeCalls.NONE, ScanQueueBypass.through(unqueued));

        adapter.doCheck(firstOnHostA, null, ScanQueueBypass.alreadyOffScanQueue(http));

        verify(http).sendRequest(argThat((HttpRequest sent) -> sent.url().equals(oauth.url())));
        verify(unqueued, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void aConnectionIdTheScannersHttpUsesIsNeverSentThroughTheUnqueuedHttp() {
        ConnectionReuse reuse = ConnectionReuse.withoutLocalAnswers();
        Http audit = answeringHttp1();
        Http unqueuedBurp = answeringHttp1();
        HttpRequest oauth = HttpRequest.httpRequestFromUrl("https://a.test/register");
        HttpRequest mcp = HttpRequest.httpRequestFromUrl("https://a.test/mcp");
        HostCheckAdapter adapter = new HostCheckAdapter(AdapterFixtures.settingsAllowing(true), McpEventLog.noop(),
                new SendingHostCheck(http -> {
                    for (int send = 0; send < 3; send++) {
                        http.sendRequest(mcp);
                        OutsideScanQueue.send(http, oauth);
                    }
                }), CheckInstrumentation.NONE, UpstreamExchanges.NONE, reuse, IssueDestination.NONE,
                new ScanNotices(), ProbeCalls.NONE,
                ScanQueueBypass.through(ConnectionReusingHttp.around(unqueuedBurp, reuse)));

        adapter.doCheck(firstOnHostA, null, audit);

        assertThat(connectionIds(audit)).isNotEmpty().doesNotContainAnyElementsOf(connectionIds(unqueuedBurp));
    }

    private static Http answeringHttp1() {
        HttpResponse response = mock(HttpResponse.class);
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.statusCode()).thenReturn((short) 200);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.response()).thenReturn(response);
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(exchange);
        when(http.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(exchange);
        return http;
    }

    private static List<String> connectionIds(Http http) {
        ArgumentCaptor<String> ids = ArgumentCaptor.forClass(String.class);
        verify(http, atLeast(0)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), ids.capture());
        return ids.getAllValues();
    }

    private static HostCheckAdapter adapterFor(RecordingChecks.Host check, boolean enabled) {
        return new HostCheckAdapter(AdapterFixtures.settingsAllowing(enabled), McpEventLog.noop(), check);
    }

    private static final class FlakyHostCheck implements HostCheck {

        private final AuditIssue issue;
        private final AtomicInteger attempts = new AtomicInteger();

        private FlakyHostCheck(AuditIssue issue) {
            this.issue = issue;
        }

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("flaky", CheckKind.HOST);
        }

        @Override
        public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
            return true;
        }

        @Override
        public String appliesOnlyTo() {
            return "any request";
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
            if (attempts.incrementAndGet() == 1) {
                throw new IllegalStateException("transient");
            }
            return List.of(issue);
        }
    }

    private record SendingHostCheck(Consumer<Http> sends) implements HostCheck {

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("sending", CheckKind.HOST);
        }

        @Override
        public boolean appliesTo(HttpRequestResponse hostBaseRequestResponse) {
            return true;
        }

        @Override
        public String appliesOnlyTo() {
            return "any request";
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse hostBaseRequestResponse, Http http) {
            sends.accept(http);
            return List.of();
        }
    }
}
