package com.mcpscanner.checks.registry;

import burp.StreamingRefusalStandIn;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.checks.shared.scancontext.ScanContext;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.HostCheck;
import com.mcpscanner.checks.api.InsertionPointCheck;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.api.RecordingChecks;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.ConnectionReusingHttp;
import com.mcpscanner.http.OutsideBurpSends;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class StreamingRefusalDeliveryTest {

    private static final String URL = "https://mcp.example.test/mcp";

    private final McpEventLog eventLog = new McpEventLog(null);
    private final RecordingDestination destination = new RecordingDestination();
    private final HttpRequestResponse base = AdapterFixtures.baseOn("mcp.example.test");

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void issuesFoundAfterAMessagelessStreamingRefusalGoToTheDestinationInsteadOfBurp() {
        AuditIssue issue = mock(AuditIssue.class);
        McpCheckAdapter<?> adapter = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of(issue));

        AuditResult result = adapter.doCheck(base, null, failingWith(messagelessRefusal()));

        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.deliveries).singleElement().satisfies(delivery -> {
            assertThat(delivery.check()).isSameAs(adapter);
            assertThat(delivery.issues()).containsExactly(issue);
        });
    }

    @Test
    void aStreamingRefusalNamedInTheMessageIsRecognisedToo() {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of(issue))
                .doCheck(base, null, failingWith(new RuntimeException("Streaming response received")));

        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.issues()).containsExactly(issue);
    }

    @Test
    void divertingIssuesLogsOneLineNamingTheCheckAndTheCount() {
        adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of(mock(AuditIssue.class), mock(AuditIssue.class)))
                .doCheck(base, null, failingWith(messagelessRefusal()));

        assertThat(messages()).contains("Scan check: streaming-probe — Burp withheld a streamed reply during "
                + "this run, so its 2 issues were added to the site map directly");
    }

    @Test
    void aRefusalWarnsOncePerScanThatProbesWereSentAgainOutsideBurp() {
        McpCheckAdapter<?> adapter = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of());

        adapter.doCheck(base, null, failingWith(messagelessRefusal()));
        adapter.doCheck(base, null, failingWith(messagelessRefusal()));

        assertThat(eventLog.snapshot()).filteredOn(entry -> entry.level() == McpEventLog.Level.WARN)
                .singleElement().satisfies(entry -> assertThat(entry.message())
                        .contains("streaming-probe", "sent again outside Burp", "twice"));
    }

    @Test
    void noRefusalMeansNoResendWarning() {
        adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of()).doCheck(base, null, mock(Http.class));

        assertThat(eventLog.snapshot()).noneMatch(entry -> entry.level() == McpEventLog.Level.WARN);
    }

    @Test
    void aRefusalOnAnotherThreadIsObserved() {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(Kind.REQUEST, Probe.ON_POOL_THREAD, List.of(issue))
                .doCheck(base, null, failingWith(messagelessRefusal()));

        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.issues()).containsExactly(issue);
    }

    @Test
    void withoutARefusalIssuesAreReturnedToBurp() {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of(issue))
                .doCheck(base, null, mock(Http.class));

        assertThat(result.auditIssues()).containsExactly(issue);
        assertThat(destination.deliveries).isEmpty();
    }

    @Test
    void aCaughtFailureThatIsNotAStreamingRefusalLeavesIssuesWithBurp() {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of(issue))
                .doCheck(base, null, failingWith(new RuntimeException("Connection refused")));

        assertThat(result.auditIssues()).containsExactly(issue);
        assertThat(destination.deliveries).isEmpty();
    }

    @Test
    void issuesFoundAfterAProbeWasResentOutsideBurpGoToTheDestinationInsteadOfBurp() {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(Kind.REQUEST, Probe.RESENDING_OUTSIDE_BURP, List.of(issue))
                .doCheck(base, null, mock(Http.class));

        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.issues()).containsExactly(issue);
    }

    @Test
    void aSendOutsideBurpThatBurpDidNotRefuseLeavesIssuesWithBurp() {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(Kind.REQUEST, Probe.OPENING_ITS_OWN_STREAM_OUTSIDE_BURP, List.of(issue))
                .doCheck(base, null, mock(Http.class));

        assertThat(result.auditIssues()).containsExactly(issue);
        assertThat(destination.deliveries).isEmpty();
    }

    @Test
    void aRefusalWithoutIssuesDeliversNothing() {
        AuditResult result = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of())
                .doCheck(base, null, failingWith(messagelessRefusal()));

        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.deliveries).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void everyCheckKindDivertsIssuesAfterARefusal(Kind kind) {
        AuditIssue issue = mock(AuditIssue.class);

        AuditResult result = adapter(kind, Probe.ON_CHECK_THREAD, List.of(issue))
                .doCheck(base, mock(AuditInsertionPoint.class), failingWith(messagelessRefusal()));

        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.issues()).containsExactly(issue);
    }

    @Test
    void aRefusalInOneInvocationDoesNotDivertALaterInvocationsIssues() {
        AuditIssue issue = mock(AuditIssue.class);
        McpCheckAdapter<?> adapter = adapter(Kind.REQUEST, Probe.ON_CHECK_THREAD, List.of(issue));
        adapter.doCheck(base, null, failingWith(messagelessRefusal()));

        AuditResult later = adapter.doCheck(base, null, mock(Http.class));

        assertThat(later.auditIssues()).containsExactly(issue);
        assertThat(destination.deliveries).hasSize(1);
    }

    @Test
    void divertedIssuesCarryTheirUpstreamEvidence() {
        HttpRequestResponse proxied = exchange("http://127.0.0.1:40123/mcp");
        HttpRequestResponse upstream = exchange(URL);
        AuditIssue issue = AuditIssue.auditIssue("Name", "Detail", "Fix", URL,
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Fix background",
                AuditIssueSeverity.HIGH, List.of(proxied));
        UpstreamExchanges exchanges = candidate -> candidate == proxied ? Optional.of(upstream) : Optional.empty();
        McpCheckAdapter<?> adapter = new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog,
                new ProbingRequestCheck(Probe.ON_CHECK_THREAD, List.of(issue)), CheckInstrumentation.NONE,
                exchanges, ConnectionReuse.withoutLocalAnswers(), destination, new ScanNotices());

        adapter.doCheck(base, null, failingWith(messagelessRefusal()));

        assertThat(destination.issues()).singleElement().satisfies(translated ->
                assertThat(translated.requestResponses()).singleElement()
                        .extracting(HttpRequestResponse::request).isSameAs(upstream.request()));
    }

    @Test
    void anAlreadyConnectionReusingHttpGetsNoSecondReuseLayerAndItsRefusalsAreStillObserved() {
        AtomicInteger adapterReuseConsultations = new AtomicInteger();
        ConnectionReuse adapterReuse = new ConnectionReuse(request -> {
            adapterReuseConsultations.incrementAndGet();
            return false;
        });
        Http alreadyReusing = ConnectionReusingHttp.around(failingWith(messagelessRefusal()),
                ConnectionReuse.withoutLocalAnswers());
        AuditIssue issue = mock(AuditIssue.class);
        McpCheckAdapter<?> adapter = new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), eventLog,
                new ProbingRequestCheck(Probe.ON_CHECK_THREAD, List.of(issue)), CheckInstrumentation.NONE,
                UpstreamExchanges.NONE, adapterReuse, destination, new ScanNotices());

        AuditResult result = adapter.doCheck(base, null, alreadyReusing);

        assertThat(adapterReuseConsultations).hasValue(0);
        assertThat(result.auditIssues()).isEmpty();
        assertThat(destination.issues()).containsExactly(issue);
    }

    private McpCheckAdapter<?> adapter(Kind kind, Probe probe, List<AuditIssue> issues) {
        return kind.adapt(this, kind.check(probe, issues));
    }

    private static RuntimeException messagelessRefusal() {
        return new RuntimeException(new StreamingRefusalStandIn());
    }

    private static Http failingWith(RuntimeException failure) {
        return mock(Http.class, invocation -> {
            throw failure;
        });
    }

    private static HttpRequestResponse exchange(String url) {
        return HttpRequestResponse.httpRequestResponse(ImmutableHttpRequest.post(url, Map.of(), "{}"),
                mock(HttpResponse.class));
    }

    private List<String> messages() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }

    enum Kind {
        REQUEST(ProbingRequestCheck::new) {
            @Override
            McpCheckAdapter<?> adapt(StreamingRefusalDeliveryTest test, McpCheck check) {
                return new RequestCheckAdapter(AdapterFixtures.settingsAllowing(true), test.eventLog,
                        (RequestCheck) check, CheckInstrumentation.NONE, UpstreamExchanges.NONE,
                        ConnectionReuse.withoutLocalAnswers(), test.destination, new ScanNotices());
            }
        },
        INSERTION_POINT(ProbingInsertionPointCheck::new) {
            @Override
            McpCheckAdapter<?> adapt(StreamingRefusalDeliveryTest test, McpCheck check) {
                return new InsertionPointCheckAdapter(AdapterFixtures.settingsAllowing(true), test.eventLog,
                        (InsertionPointCheck) check, CheckInstrumentation.NONE, UpstreamExchanges.NONE,
                        ConnectionReuse.withoutLocalAnswers(), test.destination, new ScanNotices());
            }
        },
        HOST(ProbingHostCheck::new) {
            @Override
            McpCheckAdapter<?> adapt(StreamingRefusalDeliveryTest test, McpCheck check) {
                return new HostCheckAdapter(AdapterFixtures.settingsAllowing(true), test.eventLog,
                        (HostCheck) check, CheckInstrumentation.NONE, UpstreamExchanges.NONE,
                        ConnectionReuse.withoutLocalAnswers(), test.destination, new ScanNotices());
            }
        };

        private final CheckMaker maker;

        Kind(CheckMaker maker) {
            this.maker = maker;
        }

        McpCheck check(Probe probe, List<AuditIssue> issues) {
            return maker.make(probe, issues);
        }

        abstract McpCheckAdapter<?> adapt(StreamingRefusalDeliveryTest test, McpCheck check);
    }

    @FunctionalInterface
    interface CheckMaker {
        McpCheck make(Probe probe, List<AuditIssue> issues);
    }

    enum Probe {
        ON_CHECK_THREAD(Runnable::run),
        ON_POOL_THREAD(send -> CompletableFuture.runAsync(send).join()),
        RESENDING_OUTSIDE_BURP(Runnable::run) {
            @Override
            void sendRecoveringFromFailure(Http http) {
                OutsideBurpSends.reportRefusal(http);
                OutsideBurpSends.report(http, exchange(URL));
            }
        },
        OPENING_ITS_OWN_STREAM_OUTSIDE_BURP(Runnable::run) {
            @Override
            void sendRecoveringFromFailure(Http http) {
                OutsideBurpSends.report(http, exchange(URL));
            }
        };

        private final Consumer<Runnable> runner;

        Probe(Consumer<Runnable> runner) {
            this.runner = runner;
        }

        void sendRecoveringFromFailure(Http http) {
            runner.accept(() -> {
                try {
                    http.sendRequest(HttpRequest.httpRequestFromUrl(URL));
                } catch (RuntimeException recovered) {
                    assertThat(recovered).isNotNull();
                }
            });
        }
    }

    private static final class ProbingRequestCheck implements RequestCheck {

        private final Probe probe;
        private final List<AuditIssue> issues;

        ProbingRequestCheck(Probe probe, List<AuditIssue> issues) {
            this.probe = probe;
            this.issues = issues;
        }

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("streaming-probe", CheckKind.REQUEST);
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse base, Http http) {
            probe.sendRecoveringFromFailure(http);
            return issues;
        }
    }

    private static final class ProbingInsertionPointCheck implements InsertionPointCheck {

        private final Probe probe;
        private final List<AuditIssue> issues;

        ProbingInsertionPointCheck(Probe probe, List<AuditIssue> issues) {
            this.probe = probe;
            this.issues = issues;
        }

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("streaming-probe", CheckKind.INSERTION_POINT);
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse base, AuditInsertionPoint insertionPoint, Http http) {
            probe.sendRecoveringFromFailure(http);
            return issues;
        }
    }

    private static final class ProbingHostCheck implements HostCheck {

        private final Probe probe;
        private final List<AuditIssue> issues;

        ProbingHostCheck(Probe probe, List<AuditIssue> issues) {
            this.probe = probe;
            this.issues = issues;
        }

        @Override
        public String appliesOnlyTo() {
            return "any request";
        }

        @Override
        public CheckDescriptor descriptor() {
            return RecordingChecks.descriptorFor("streaming-probe", CheckKind.HOST);
        }

        @Override
        public boolean appliesTo(HttpRequestResponse base) {
            return true;
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse base, Http http) {
            probe.sendRecoveringFromFailure(http);
            return issues;
        }
    }

    private record Delivery(ActiveScanCheck check, List<AuditIssue> issues) {
    }

    private static final class RecordingDestination implements IssueDestination {

        private final List<Delivery> deliveries = new CopyOnWriteArrayList<>();

        @Override
        public void add(ActiveScanCheck check, List<AuditIssue> issues, Optional<ScanContext> scan) {
            deliveries.add(new Delivery(check, List.copyOf(issues)));
        }

        List<AuditIssue> issues() {
            List<AuditIssue> all = new ArrayList<>();
            deliveries.forEach(delivery -> all.addAll(delivery.issues()));
            return all;
        }
    }
}
