package com.mcpscanner.engine;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.LateIssueSink;
import com.mcpscanner.checks.api.RecordingChecks;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.shared.scancontext.CurrentScan;
import com.mcpscanner.checks.shared.scancontext.ScanContext;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.checks.registry.LateIssueRouter;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.FakeCollaborator;
import com.mcpscanner.checks.shared.collaborator.InteractionWindow;
import com.mcpscanner.checks.shared.collaborator.ManualTicker;
import com.mcpscanner.checks.shared.collaborator.WatchDecision;
import com.mcpscanner.checks.shared.collaborator.WatchTiming;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.TempFileCopies;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.http.WireResolvingCopies;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static com.mcpscanner.engine.EngineFixtures.LABEL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class LateCollaboratorIssueTest {

    private static final CheckDescriptor DESCRIPTOR = RecordingChecks.descriptorFor("late-oob", CheckKind.REQUEST);
    private static final String TARGET = "https://mcp.example.test/mcp";
    private static final ScanInstrumentation ATTRIBUTING = (http, scanId, requestSent, cancelled) -> new InstrumentedScan() {
        @Override
        public Http http() {
            return http;
        }

        @Override
        public <T> T run(String testedRequest, Supplier<T> invocation) {
            return CurrentScan.within(Optional.of(new ScanContext(scanId).forRequest(testedRequest)), invocation);
        }
    };

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-11T10:00:00Z"));
    private final FakeCollaborator collaborator = new FakeCollaborator();
    private final ManualTicker ticker = new ManualTicker();
    private final McpEventLog eventLog = new McpEventLog(null);
    private final WatchTiming timing = new WatchTiming(clock, clock::advance, InteractionWindow.standard());
    private final CollaboratorWatch watch = new CollaboratorWatch(() -> Optional.of(collaborator), eventLog, ticker,
            timing);
    private final FakeSiteMap siteMap = new FakeSiteMap();
    private final List<AuditIssue> instrumented = new ArrayList<>();
    private HttpRequestResponse proxied;
    private HttpRequestResponse upstream;
    private McpScanEngine engine;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        proxied = exchange("http://127.0.0.1:40123/mcp");
        upstream = exchange(TARGET);
        engine = new McpScanEngine(mock(Http.class), base -> List.of(), siteMap, new FixedWorkers(new SameThreadExecutorService()),
                new EngineEnvironment(eventLog, Clock.systemUTC(), ATTRIBUTING, HttpRequest::url,
                        watch::watchedCount));
    }

    @Test
    void aLateIssueLandsOnTheFinishedScanThatSentItsPayload() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        EngineScan first = startScan(sent);
        EngineScan second = startScan(sent);

        collaborator.interact(sent.get(0), InteractionType.HTTP);
        ticker.tick();

        assertThat(first.snapshot().issues().kept()).extracting(AuditIssue::name).containsExactly("Late interaction");
        assertThat(first.snapshot().issues().count(AuditIssueSeverity.HIGH)).isEqualTo(1);
        assertThat(second.snapshot().issues().total()).isZero();
    }

    @Test
    void aLateIssueIsCreditedWithTheNameOfTheRequestItsInvocationScanned() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        EngineScan scan = startScan(sent);

        collaborator.interact(sent.get(0), InteractionType.HTTP);
        ticker.tick();

        ScanFindings findings = scan.snapshot().issues();
        assertThat(findings.testedRequest(findings.kept().get(0))).contains(proxied.request().url());
    }

    @Test
    void aLateDuplicateTheSiteMapAlreadyHoldsIsNotCountedForItsScan() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        EngineScan first = startScan(sent);
        EngineScan second = startScan(sent);

        sent.forEach(payload -> collaborator.interact(payload, InteractionType.HTTP));
        ticker.tick();

        assertThat(first.snapshot().issues().total() + second.snapshot().issues().total()).isEqualTo(1);
    }

    @Test
    void eachScanCountsOnlyItsOwnPayloadsStillWatched() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        EngineScan first = startScan(sent);
        EngineScan second = startScan(sent);

        collaborator.interact(sent.get(0), InteractionType.HTTP);
        ticker.tick();

        assertThat(first.snapshot().progress().watchedPayloads()).isZero();
        assertThat(second.snapshot().progress().watchedPayloads()).isEqualTo(sent.size() - 1);
    }

    @Test
    void aLateIssueFromAProbeSentOutsideAnExtensionScanOnlyReachesTheSiteMap() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        EngineScan scan = startScan(sent);
        engine.addIssues(FakeCheck.named("burp"), List.of(issueWith(upstream)), Optional.empty());

        assertThat(siteMap.added()).hasSize(1);
        assertThat(scan.snapshot().issues().total()).isZero();
    }

    @Test
    void anInteractionAfterTheScanFinishedAddsAnIssueWithUpstreamEvidenceToTheSiteMap() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        scanWith(sent);
        assertThat(siteMap.added()).isEmpty();

        collaborator.interact(sent.get(0), InteractionType.HTTP);
        ticker.tick();

        assertThat(siteMap.added()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("Late interaction");
            assertThat(issue.requestResponses()).singleElement()
                    .extracting(HttpRequestResponse::request).isSameAs(upstream.request());
        });
        assertThat(instrumented).hasSize(1);
        assertThat(keptMessages()).anyMatch(message -> message.contains("late-oob")
                && message.contains("reported 1 issue after its invocation finished"));
    }

    @Test
    void consolidatesALateIssueAgainstTheSiteMapLikeAReturnedOne() {
        List<CollaboratorPayload> sent = new ArrayList<>();
        scanWith(sent);
        scanWith(sent);

        sent.forEach(payload -> collaborator.interact(payload, InteractionType.HTTP));
        ticker.tick();

        assertThat(siteMap.added()).hasSize(1);
    }

    @Test
    void theFinishedScanCountsThePayloadsStillWatched() {
        List<CollaboratorPayload> sent = new ArrayList<>();

        ScanProgress progress = scanWith(sent);

        assertThat(progress.watchedPayloads()).isEqualTo(1);
        assertThat(eventLog.snapshot()).anyMatch(entry -> entry.message().contains(
                "1 Collaborator payload still being watched for up to 15 min; late issues will be added to the site map"));
    }

    @Test
    void aLateIssueWhoseScanLeftTheHistoryStillReachesTheSiteMap() {
        engine.addIssues(FakeCheck.named("late"), List.of(issueWith(upstream)),
                Optional.of(new ScanCredit(404, Optional.empty())));

        assertThat(siteMap.added()).hasSize(1);
        assertThat(engine.history().snapshots()).isEmpty();
    }

    @Test
    void aLateIssueOnAStreamableHttpBaseSentThroughTheProxyIsFiledUnderTheTargetUrl() {
        UpstreamExchanges stored = upstreamOfProxied().proxiedThrough(() -> HttpService.httpService("127.0.0.1", 40123, false));
        CollaboratorWatch resolvingWatch = new CollaboratorWatch(() -> Optional.of(collaborator), eventLog, ticker,
                timing, new WireResolvingCopies(TempFileCopies.IN_MEMORY, stored));
        List<CollaboratorPayload> sent = new ArrayList<>();
        startScan(sent, resolvingWatch, stored,
                (base, kept) -> issueFiledUnder(base.request().url(), kept)).completion().join();

        collaborator.interact(sent.get(0), InteractionType.HTTP);
        ticker.tick();

        assertThat(siteMap.added()).singleElement().satisfies(issue -> {
            assertThat(URI.create(issue.baseUrl())).extracting(URI::getScheme, URI::getHost, URI::getPath)
                    .containsExactly("https", "mcp.example.test", "/mcp");
            assertThat(issue.requestResponses()).singleElement()
                    .satisfies(evidence -> assertThat(evidence.request().url()).isEqualTo(issue.baseUrl()));
        });
    }

    private UpstreamExchanges upstreamOfProxied() {
        return candidate -> candidate == proxied ? List.of(upstream) : List.of();
    }

    private ScanProgress scanWith(List<CollaboratorPayload> sent) {
        return startScan(sent).completion().join();
    }

    private EngineScan startScan(List<CollaboratorPayload> sent) {
        return startScan(sent, watch, upstreamOfProxied(), (base, kept) -> issueWith(base));
    }

    private EngineScan startScan(List<CollaboratorPayload> sent, CollaboratorWatch scanWatch,
                                 UpstreamExchanges upstreamExchanges, LateIssueFiling filing) {
        LateIssueRouter router = new LateIssueRouter(EngineFixtures.siteMapOf(engine));
        CheckServices services = CheckServices.standalone().reportingLateIssues(scanWatch, router);
        CheckCatalog catalog = CheckCatalog.of(List.of((CheckFactory) granted ->
                new WatchingCheck(granted.collaboratorWatch(), granted.lateIssues(), sent, filing)), services);
        ScanCheckRegistry registry = new ScanCheckRegistry(catalog,
                new ScanCheckSettings(InMemoryPersistedObject.configStore()), eventLog, recordingInstrumentation(),
                upstreamExchanges, ConnectionReuse.withoutLocalAnswers(), EngineFixtures.siteMapOf(engine));
        router.routeThrough(registry);
        registry.registerWith(engine::register);
        return engine.scan(List.of(proxied), LABEL);
    }

    private CheckInstrumentation recordingInstrumentation() {
        return new CheckInstrumentation() {
            @Override
            public Http probeHttp(String checkId, Http http) {
                return http;
            }

            @Override
            public void reported(String checkId, List<AuditIssue> issues) {
                instrumented.addAll(issues);
            }
        };
    }

    private List<String> keptMessages() {
        return eventLog.snapshot().stream().filter(McpEventLog.LogEntry::kept)
                .map(McpEventLog.LogEntry::message).toList();
    }

    private final class WatchingCheck implements RequestCheck {

        private final CollaboratorWatch checkWatch;
        private final LateIssueSink lateIssues;
        private final List<CollaboratorPayload> sent;
        private final LateIssueFiling filing;

        WatchingCheck(CollaboratorWatch checkWatch, LateIssueSink lateIssues, List<CollaboratorPayload> sent,
                      LateIssueFiling filing) {
            this.checkWatch = checkWatch;
            this.lateIssues = lateIssues;
            this.sent = sent;
            this.filing = filing;
        }

        @Override
        public CheckDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse base, Http http) {
            CollaboratorPayload payload = checkWatch.probing(source -> source.newPayload().orElseThrow());
            sent.add(payload);
            HttpRequestResponse kept = checkWatch.kept(base);
            checkWatch.watch(List.of(payload), observed -> {
                lateIssues.report(this, List.of(filing.issue(base, kept)));
                return WatchDecision.DONE;
            });
            return List.of();
        }
    }

    @FunctionalInterface
    private interface LateIssueFiling {
        AuditIssue issue(HttpRequestResponse base, HttpRequestResponse kept);
    }

    private static AuditIssue issueWith(HttpRequestResponse evidence) {
        return issueFiledUnder(TARGET, evidence);
    }

    private static AuditIssue issueFiledUnder(String baseUrl, HttpRequestResponse evidence) {
        return AuditIssue.auditIssue("Late interaction", "Detail", "Fix", baseUrl, AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM, "Background", "Fix background", AuditIssueSeverity.HIGH,
                List.of(evidence));
    }

    private static HttpRequestResponse exchange(String url) {
        return HttpRequestResponse.httpRequestResponse(ImmutableHttpRequest.post(url, Map.of(), "{}"),
                mock(HttpResponse.class));
    }
}
