package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.SendOnlyBurpHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static com.mcpscanner.testutil.AwaitedFutures.valueWithin;
import static com.mcpscanner.testutil.Polling.within;
import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.AccessFixtures.CAROL;
import static com.mcpscanner.access.AccessFixtures.DAVE;
import static com.mcpscanner.access.AccessFixtures.readOnlyTool;
import static com.mcpscanner.access.AccessFixtures.resource;
import static com.mcpscanner.access.AccessFixtures.tool;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CheckAccessRunnerTest {

    private static final Duration WAIT = Duration.ofSeconds(5);
    private static final String ENDPOINT = "https://mcp.test/mcp";
    private static final WriteReplayApproval NEVER_ASKED = tools -> {
        throw new AssertionError("no write tool should prompt");
    };

    private final RecordingHttp http = new RecordingHttp();
    private final RecordingComparison check = new RecordingComparison();
    private final List<AuditIssue> siteMap = new CopyOnWriteArrayList<>();
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
    private final Listener listener = new Listener();
    private AccessFixtures fixtures;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
        fixtures = new AccessFixtures().compare(BOB, DAVE);
    }

    @AfterEach
    void stopExecutor() {
        runs.shutdown();
    }

    @Test
    void comparesEachRowsOwnerExchangeOnceInOneComparisonRunAndAddsItsIssuesToTheSiteMap() throws Exception {
        List<AccessRow> rows = rows(List.of(readOnlyTool("search")), List.of(resource("notes://a")));

        runner().start(rows, NEVER_ASKED, listener).orElseThrow();

        AccessRunSummary summary = awaitFinished();
        assertThat(check.compared).extracting(HttpRequest::bodyToString)
                .containsExactlyInAnyOrder(body("search"), body("notes://a"));
        assertThat(check.begun).hasValue(1);
        assertThat(check.closed).hasValue(1);
        assertThat(check.compared).allSatisfy(base -> {
            assertThat(base.headerValue("Authorization")).isEqualTo("Bearer alice-token");
            assertThat(base.hasHeader(ScannerSentinels.IDENTITY_HEADER)).isFalse();
        });
        assertThat(siteMap).hasSize(2);
        assertThat(summary).isEqualTo(new AccessRunSummary(2, 2, 2, false));
        assertThat(listener.progress).containsExactly("1/2", "2/2");
    }

    @Test
    void rowOwnedByAHigherIdentityIsCheckedFromThatIdentitysOwnRequest() throws Exception {
        fixtures.lists(ALICE, List.of(), List.of()).lists(BOB, List.of(), List.of())
                .lists(DAVE, List.of(readOnlyTool("admin")), List.of());
        List<AccessRow> rows = fixtures.matrix().snapshot().rows();

        runner().start(rows, NEVER_ASKED, listener);

        awaitFinished();
        HttpRequest base = check.compared.get(0);
        assertThat(base.headerValue("Authorization")).isEqualTo("Bearer dave-token");
        assertThat(base.headerValue(ScannerSentinels.IDENTITY_HEADER)).isEqualTo(DAVE.id());
        assertThat(base.hasHeader(McpHeaders.SESSION_ID)).isFalse();
    }

    @Test
    void writeToolsPromptOnceAndDecliningRunsNothing() {
        AtomicInteger prompts = new AtomicInteger();
        List<AccessRow> rows = rows(List.of(tool("delete"), tool("archive"), readOnlyTool("search")), List.of());

        var run = runner().start(rows, tools -> {
            prompts.incrementAndGet();
            assertThat(tools).extracting(McpToolDefinition::name).containsExactly("delete", "archive");
            return false;
        }, listener);

        assertThat(run).isEmpty();
        assertThat(prompts).hasValue(1);
        assertThat(http.sent).isEmpty();
        assertThat(confirmations.confirmed("delete")).isFalse();
    }

    @Test
    void approvedWriteToolsAreConfirmedForReplay() throws Exception {
        List<AccessRow> rows = rows(List.of(tool("delete")), List.of());

        runner().start(rows, tools -> true, listener);

        awaitFinished();
        assertThat(confirmations.confirmed("delete")).isTrue();
        assertThat(check.compared).hasSize(1);
    }

    @Test
    void itemsAreComparedFourAtATime() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b", "c", "d", "e", "f"), List.of());
        check.holdEveryCompare();

        runner().start(rows, NEVER_ASKED, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 4);
        assertThat(check.compared).hasSize(4);
        check.release();

        AccessRunSummary summary = awaitFinished();
        assertThat(summary).isEqualTo(new AccessRunSummary(6, 6, 6, false));
        assertThat(check.mostInFlight).hasValue(4);
        assertThat(listener.progress).containsExactly("1/6", "2/6", "3/6", "4/6", "5/6", "6/6");
    }

    @Test
    void writeToolsAreCheckedOnlyAfterEveryReadItemIsDone() throws Exception {
        List<AccessRow> rows = rows(List.of(tool("delete"), readOnlyTool("a"), readOnlyTool("b")), List.of());
        check.holdEveryCompare();

        runner().start(rows, tools -> true, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 2);

        assertThat(check.compared).extracting(HttpRequest::bodyToString)
                .containsExactlyInAnyOrder(body("a"), body("b"));
        check.release();
        awaitFinished();
        assertThat(check.compared).extracting(HttpRequest::bodyToString).last().isEqualTo(body("delete"));
    }

    @Test
    void anUnannotatedToolThatMayOnlyReadIsCheckedBeforeAnyDestructiveToolListedAheadOfIt() throws Exception {
        List<AccessRow> rows = rows(List.of(tool("delete_note"), tool("update_note"), tool("get_note")), List.of());

        runner().start(rows, tools -> true, listener).orElseThrow();
        awaitFinished();

        assertThat(check.compared).extracting(HttpRequest::bodyToString)
                .containsExactly(body("get_note"), body("update_note"), body("delete_note"));
    }

    @Test
    void writeToolsAreCheckedOneAtATime() throws Exception {
        List<AccessRow> rows = rows(List.of(tool("delete"), tool("update"), tool("send")), List.of());
        check.holdEveryCompare();

        runner().start(rows, tools -> true, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 1);
        check.release();

        assertThat(awaitFinished()).isEqualTo(new AccessRunSummary(3, 3, 3, false));
        assertThat(check.mostInFlight).hasValue(1);
    }

    @Test
    void cancellingLetsTheItemsBeingCheckedFinishAndStartsNoOthers() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b", "c", "d", "e", "f"), List.of());
        check.holdEveryCompare();

        AccessRun run = runner().start(rows, NEVER_ASKED, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 4);
        run.cancel();
        check.release();

        AccessRunSummary summary = awaitFinished();
        assertThat(summary.cancelled()).isTrue();
        assertThat(summary.checked()).isEqualTo(4);
        assertThat(check.compared).hasSize(4);
        assertThat(check.closed).hasValue(1);
    }

    @Test
    void disconnectCancelsRunAndNoFurtherBaselinesAreSent() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b", "c", "d", "e", "f"), List.of());
        check.holdEveryCompare();

        runner().start(rows, NEVER_ASKED, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 4);
        runs.cancelAll();
        check.release();

        AccessRunSummary summary = awaitFinished();
        assertThat(summary.cancelled()).isTrue();
        assertThat(http.sent).extracting(HttpRequest::bodyToString)
                .containsExactlyInAnyOrder(body("a"), body("b"), body("c"), body("d"));
    }

    @Test
    void shutdownInterruptsTheItemsBeingCheckedAndEndsTheRun() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b"), List.of());
        check.holdEveryCompare();

        runner().start(rows, NEVER_ASKED, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 2);
        runs.shutdown();

        assertThat(awaitFinished().cancelled()).isTrue();
        assertThat(check.interrupted).isTrue();
        assertThat(check.closed).hasValue(1);
    }

    @Test
    void writeBaselineIsNotSentOnceItsConfirmationIsWithdrawn() throws Exception {
        List<AccessRow> rows = rows(List.of(readOnlyTool("a"), readOnlyTool("b"), readOnlyTool("c"),
                readOnlyTool("d"), tool("delete")), List.of());
        check.holdEveryCompare();

        runner().start(rows, tools -> true, listener).orElseThrow();
        within(WAIT).until(() -> check.inFlight.get() == 4);
        confirmations.clear();
        check.release();

        awaitFinished();
        assertThat(http.sent).extracting(HttpRequest::bodyToString).doesNotContain(body("delete"));
        assertThat(check.compared).hasSize(4);
    }

    @Test
    void discoversComparedUsersOnceBeforeSendingAnything() throws Exception {
        List<Integer> sentWhenDiscovering = new java.util.concurrent.CopyOnWriteArrayList<>();
        List<AccessRow> rows = rows(readOnlyTools("search", "export"), List.of());

        new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs, McpEventLog.noop(),
                UpstreamExchanges.NONE, () -> new AccessSnapshot(false, List.of(), List.of()),
                () -> sentWhenDiscovering.add(http.sent.size())).start(rows, NEVER_ASKED, listener);

        awaitFinished();
        assertThat(sentWhenDiscovering).containsExactly(0);
    }

    @Test
    void checksTheRowsAsTheyStandAfterDiscoveringTheComparedUsers() throws Exception {
        List<McpToolDefinition> tools = readOnlyTools("search");
        List<AccessRow> beforeDiscovery = new AccessFixtures().compare(BOB).lists(ALICE, tools, List.of())
                .matrix().snapshot().rows();
        AccessMatrix afterDiscovery = new AccessFixtures().compare(BOB).lists(ALICE, List.of(), List.of())
                .lists(BOB, tools, List.of()).matrix();
        AtomicBoolean discovered = new AtomicBoolean();
        Supplier<AccessSnapshot> results = () -> discovered.get()
                ? afterDiscovery.snapshot()
                : new AccessSnapshot(false, List.of(), List.of());
        WriteReplays replays = new WriteReplays(confirmations, new MatrixAccessLedger(afterDiscovery, confirmations));
        OwnerRequests requests = new OwnerRequests(CheckAccessRunnerTest::primaryRequest,
                new IdentityRequests(() -> PrincipalRoster.of(ALICE, List.of(BOB))));

        new CheckAccessRunner(check, http, requests, siteMap::add, replays, runs, McpEventLog.noop(),
                UpstreamExchanges.NONE, results, () -> discovered.set(true)).start(beforeDiscovery, NEVER_ASKED,
                listener);

        awaitFinished();
        assertThat(http.sent).first().extracting(request -> request.headerValue("Authorization"))
                .isEqualTo("Bearer bob-token");
    }

    @Test
    void alsoChecksItemsOnlyTheNewlyDiscoveredComparedUsersList() throws Exception {
        List<McpToolDefinition> shared = readOnlyTools("search");
        List<McpToolDefinition> bobsOnly = readOnlyTools("bob_report");
        AccessMatrix matrix = new AccessFixtures().compare(BOB).lists(ALICE, shared, List.of())
                .lists(BOB, java.util.stream.Stream.concat(shared.stream(), bobsOnly.stream()).toList(), List.of())
                .matrix();
        List<AccessRow> beforeDiscovery = new AccessFixtures().compare(BOB).lists(ALICE, shared, List.of())
                .matrix().snapshot().rows();
        AtomicBoolean discovered = new AtomicBoolean();
        Supplier<AccessSnapshot> results = () -> discovered.get() ? matrix.snapshot()
                : new AccessSnapshot(true, List.of(), beforeDiscovery);
        WriteReplays replays = new WriteReplays(confirmations, new MatrixAccessLedger(matrix, confirmations));
        OwnerRequests requests = new OwnerRequests(CheckAccessRunnerTest::primaryRequest,
                new IdentityRequests(() -> PrincipalRoster.of(ALICE, List.of(BOB))));

        new CheckAccessRunner(check, http, requests, siteMap::add, replays, runs, McpEventLog.noop(),
                UpstreamExchanges.NONE, results, () -> discovered.set(true)).start(beforeDiscovery, NEVER_ASKED,
                listener);

        assertThat(awaitFinished().total()).isEqualTo(2);
        assertThat(http.sent).extracting(HttpRequest::bodyToString)
                .contains(body("search"), body("bob_report"));
    }

    @Test
    void checkingOneItemDoesNotPullInItemsDiscoveryRevealsForOtherRows() throws Exception {
        List<McpToolDefinition> shared = readOnlyTools("search", "export");
        List<McpToolDefinition> bobsOnly = readOnlyTools("bob_report");
        AccessMatrix matrix = new AccessFixtures().compare(BOB).lists(ALICE, shared, List.of())
                .lists(BOB, java.util.stream.Stream.concat(shared.stream(), bobsOnly.stream()).toList(), List.of())
                .matrix();
        List<AccessRow> beforeDiscovery = new AccessFixtures().compare(BOB).lists(ALICE, shared, List.of())
                .matrix().snapshot().rows();
        List<AccessRow> onlySearch = beforeDiscovery.stream()
                .filter(row -> row.item().key().name().equals("search")).toList();
        AtomicBoolean discovered = new AtomicBoolean();
        Supplier<AccessSnapshot> results = () -> discovered.get() ? matrix.snapshot()
                : new AccessSnapshot(true, List.of(), beforeDiscovery);
        WriteReplays replays = new WriteReplays(confirmations, new MatrixAccessLedger(matrix, confirmations));
        OwnerRequests requests = new OwnerRequests(CheckAccessRunnerTest::primaryRequest,
                new IdentityRequests(() -> PrincipalRoster.of(ALICE, List.of(BOB))));

        new CheckAccessRunner(check, http, requests, siteMap::add, replays, runs, McpEventLog.noop(),
                UpstreamExchanges.NONE, results, () -> discovered.set(true)).start(onlySearch, NEVER_ASKED,
                listener);

        assertThat(awaitFinished().total()).isEqualTo(1);
        assertThat(http.sent).extracting(HttpRequest::bodyToString).containsOnly(body("search"));
    }

    @Test
    void logsEachItemsOwnerRequestAndComparisonProbesAtDebugLevel() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("search"), List.of());
        check.sendDuringEveryCompare(ImmutableHttpRequest.post(ENDPOINT, Map.of(), "probe"));
        McpEventLog eventLog = new McpEventLog(null);

        new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs, eventLog)
                .start(rows, NEVER_ASKED, listener);

        awaitFinished();
        assertThat(eventLog.snapshot()).filteredOn(entry -> entry.level() == McpEventLog.Level.DEBUG)
                .extracting(McpEventLog.LogEntry::message)
                .anyMatch(message -> message.matches("Check access search: 2 requests, \\d+\\.\\d{2} s"));
    }

    @Test
    void logsOneInfoLineListingItemsALowerUserReachesUnderAnInferredExpectation() throws Exception {
        AccessMatrix matrix = new AccessFixtures().compare(CAROL)
                .lists(ALICE, readOnlyTools("search", "export"), List.of())
                .lists(CAROL, readOnlyTools("search", "export"), List.of()).matrix();
        matrix.record(AccessFixtures.toolKey("search"), CAROL.id(), AccessOutcome.SAME_RESULT);
        matrix.record(AccessFixtures.toolKey("export"), CAROL.id(), AccessOutcome.REFUSED);
        McpEventLog eventLog = new McpEventLog(null);

        new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs, eventLog,
                UpstreamExchanges.NONE, matrix::snapshot).start(matrix.snapshot().rows(), NEVER_ASKED, listener);

        awaitFinished();
        assertThat(eventLog.snapshot()).filteredOn(entry -> entry.level() == McpEventLog.Level.INFO)
                .extracting(McpEventLog.LogEntry::message)
                .filteredOn(message -> message.contains("only inferred"))
                .containsExactly("Check access: a lower-privilege user gets the owner's result and who should "
                        + "reach it is only inferred; confirm Who should reach it for search");
    }

    @Test
    void anHttp429OnAnOwnerRequestStopsTheWholeRun() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b", "c", "d", "e", "f", "g", "h"), List.of());
        http.rateLimitEveryRequest();
        McpEventLog eventLog = new McpEventLog(null);

        new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs, eventLog)
                .start(rows, NEVER_ASKED, listener);

        AccessRunSummary summary = awaitFinished();
        assertThat(http.sent).hasSizeLessThanOrEqualTo(ParallelItems.PARALLELISM);
        assertThat(check.compared).isEmpty();
        assertThat(summary.checked()).isLessThan(rows.size());
        assertThat(summary.stopReason()).hasValueSatisfying(reason ->
                assertThat(reason).isEqualTo("the server answered HTTP 429 Too Many Requests"));
        assertThat(check.closed).hasValue(1);
        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .filteredOn(message -> message.startsWith("Check access stopped"))
                .singleElement().asString()
                .startsWith("Check access stopped: the server answered HTTP 429 Too Many Requests (");
    }

    @Test
    void anHttp429WithAShortRetryAfterIsWaitedOutAndTheRunContinues() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b"), List.of());
        http.rateLimitFirstRequestAsking("0");
        McpEventLog eventLog = new McpEventLog(null);

        new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs, eventLog)
                .start(rows, NEVER_ASKED, listener);

        AccessRunSummary summary = awaitFinished();
        assertThat(summary.stopReason()).isEmpty();
        assertThat(summary.checked()).isEqualTo(2);
        assertThat(check.compared).hasSize(2);
        assertThat(http.sent).hasSize(3);
        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .contains("Check access — HTTP 429 from mcp.test: waiting 0 s as Retry-After asks, then resending");
    }

    @Test
    void cancellingTheRunEndsARetryAfterWaitWithoutResending() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a"), List.of());
        http.rateLimitAsking(body("a"), "60");
        McpEventLog eventLog = new McpEventLog(null);

        AccessRun run = new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs,
                eventLog).start(rows, NEVER_ASKED, listener).orElseThrow();
        within(WAIT).until(() -> eventLog.snapshot().stream()
                .anyMatch(entry -> entry.message().contains("waiting 60 s as Retry-After asks")));
        run.cancel();

        awaitFinished();
        assertThat(http.sent).hasSize(1);
    }

    @Test
    void anotherItemsUnhonouredHttp429EndsARetryAfterWaitWithoutResending() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b"), List.of());
        http.rateLimitAsking(body("a"), "60");
        http.rateLimit(body("b"));

        runner().start(rows, NEVER_ASKED, listener);

        AccessRunSummary summary = awaitFinished();
        assertThat(summary.stopReason()).isPresent();
        assertThat(http.sent).filteredOn(request -> request.bodyToString().equals(body("a")))
                .hasSizeLessThanOrEqualTo(1);
    }

    @Test
    void anHttp429DuringAComparisonStopsTheWholeRun() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b", "c", "d", "e", "f", "g", "h"), List.of());
        HttpRequest probe = ImmutableHttpRequest.post(ENDPOINT, Map.of(), "probe");
        check.sendDuringEveryCompare(probe);
        http.rateLimit("probe");

        runner().start(rows, NEVER_ASKED, listener);

        AccessRunSummary summary = awaitFinished();
        assertThat(http.sent).filteredOn(request -> request.bodyToString().equals("probe")).hasSizeBetween(1, 4);
        assertThat(http.sent).extracting(HttpRequest::bodyToString)
                .doesNotContain(body("e"), body("f"), body("g"), body("h"));
        assertThat(summary.checked()).isLessThan(rows.size());
    }

    @Test
    void failureOnOneRowDoesNotStopTheOthers() throws Exception {
        List<AccessRow> rows = rows(List.of(readOnlyTool("broken"), readOnlyTool("fine")), List.of());
        http.failFor(body("broken"));

        runner().start(rows, NEVER_ASKED, listener);

        AccessRunSummary summary = awaitFinished();
        assertThat(summary.checked()).isEqualTo(2);
        assertThat(summary.stopReason()).isEmpty();
        assertThat(check.compared).extracting(HttpRequest::bodyToString).containsExactly(body("fine"));
    }

    @Test
    void theSameTransportFailureOnConsecutiveItemsStopsTheRunWithOneLine() throws Exception {
        List<AccessRow> rows = rows(readOnlyTools("a", "b", "c", "d", "e", "f", "g", "h"), List.of());
        http.failEveryRequestWith("Streaming response received");
        McpEventLog eventLog = new McpEventLog(null);

        new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs, eventLog)
                .start(rows, NEVER_ASKED, listener);

        AccessRunSummary summary = awaitFinished();
        assertThat(http.sent).hasSizeBetween(2, ParallelItems.PARALLELISM + 1);
        assertThat(summary.checked()).isEqualTo(http.sent.size());
        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .filteredOn(message -> message.contains("Streaming response received"))
                .satisfiesExactly(
                        failed -> assertThat(failed).matches("Check access failed for [a-h]: Streaming response received"),
                        stopped -> assertThat(stopped).isEqualTo("Check access stopped: Streaming response received ("
                                + summary.checked() + " of 8 items checked)"));
    }

    @Test
    void toolArgumentsAreFilledFromTheOwnersOwnedObjects() throws Exception {
        String schema = "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}}}";
        Principal alice = new Principal(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY, ALICE.credentialHeaders(),
                Optional.empty(), Map.of("doc_id", "d-alice-0001"));
        AccessFixtures owned = new AccessFixtures().withPrimary(alice).compare(BOB)
                .lists(alice, List.of(new McpToolDefinition("get_document", "", schema)), List.of());
        fixtures = owned;
        List<ScanTarget> rendered = new CopyOnWriteArrayList<>();

        new CheckAccessRunner(check, http, new OwnerRequests(target -> {
            rendered.add(target);
            return primaryRequest(target);
        }, new IdentityRequests(owned::roster)), siteMap::add, writeReplays(), runs, McpEventLog.noop())
                .start(owned.matrix().snapshot().rows(), tools -> true, listener);

        awaitFinished();
        McpToolDefinition tool = ((ScanTarget.Tool) rendered.get(0)).tool();
        assertThat(tool.inputSchema()).contains("\"default\":\"d-alice-0001\"");
    }

    @Test
    void issuesReachTheSiteMapWithTheirUpstreamEvidence() throws Exception {
        List<AccessRow> rows = rows(List.of(readOnlyTool("search")), List.of());
        HttpRequestResponse upstream = HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post("https://target.test/mcp", Map.of(), "{}"), null);
        check.citeBaseAsEvidence();
        OwnerRequests requests = new OwnerRequests(CheckAccessRunnerTest::primaryRequest,
                new IdentityRequests(fixtures::roster));

        new CheckAccessRunner(check, http, requests, siteMap::add, writeReplays(), runs, McpEventLog.noop(),
                proxied -> Optional.of(upstream)).start(rows, NEVER_ASKED, listener);

        awaitFinished();
        assertThat(siteMap).singleElement().satisfies(issue -> assertThat(issue.requestResponses())
                .singleElement().extracting(HttpRequestResponse::request).isSameAs(upstream.request()));
    }

    private AccessRunSummary awaitFinished() {
        return valueWithin(WAIT, listener.finished);
    }

    private static List<McpToolDefinition> readOnlyTools(String... names) {
        return java.util.Arrays.stream(names).map(AccessFixtures::readOnlyTool).toList();
    }

    private List<AccessRow> rows(List<McpToolDefinition> tools, List<com.mcpscanner.mcp.McpResourceDefinition> resources) {
        return fixtures.lists(ALICE, tools, resources).matrix().snapshot().rows();
    }

    private CheckAccessRunner runner() {
        return new CheckAccessRunner(check, http, ownerRequests(), siteMap::add, writeReplays(), runs,
                McpEventLog.noop());
    }

    private OwnerRequests ownerRequests() {
        return new OwnerRequests(CheckAccessRunnerTest::primaryRequest, new IdentityRequests(fixtures::roster));
    }

    private WriteReplays writeReplays() {
        return new WriteReplays(confirmations, new MatrixAccessLedger(fixtures.matrix(), confirmations));
    }

    private static HttpRequest primaryRequest(ScanTarget target) {
        return ImmutableHttpRequest.post(ENDPOINT, Map.of("Authorization", "Bearer alice-token",
                McpHeaders.SESSION_ID, "primary-session"), body(target.identifier()));
    }

    private static String body(String identifier) {
        return "{\"call\":\"" + identifier + "\"}";
    }

    private static final class Listener implements AccessRunListener {
        private final List<String> progress = new CopyOnWriteArrayList<>();
        private final CompletableFuture<AccessRunSummary> finished = new CompletableFuture<>();

        @Override
        public void progress(int done, int total) {
            progress.add(done + "/" + total);
        }

        @Override
        public void finished(AccessRunSummary summary) {
            finished.complete(summary);
        }
    }


}
