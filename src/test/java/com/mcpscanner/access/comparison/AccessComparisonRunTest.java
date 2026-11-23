package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.access.AccessRunStopped;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.CallerServer;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.method;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.principal;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.session;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static com.mcpscanner.testutil.AwaitedFutures.doneWithin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AccessComparisonRunTest {

    private static final String LIVE_SESSION = "sess-live";
    private static final String MARKER = "ALICE-PRIVATE-7f3c";
    private static final Principal PEER = ComparisonHarness.peer("B");
    private static final Principal SAME_AS_OWNER = new Principal("c", "identity-C", PrincipalRole.PEER,
            () -> Map.of("Authorization", "Bearer A"), Optional.empty(), Map.of());

    private final McpEventLog eventLog = new McpEventLog(null);
    private final RecordingLedger ledger = new RecordingLedger();
    private final List<Principal> compared = new ArrayList<>(List.of(PEER));
    private Principal owner = ComparisonHarness.owner(Optional.empty());

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void statelessItemSendsOneReplayPerIdentityAndOneAnonymousRequest() {
        CallerServer server = CallerServer.stateless(caller -> FakeReply.result("note for everyone"));
        FakeMcpTarget target = new FakeMcpTarget(server);

        try (AccessComparisonRun run = check().begin(target.http())) {
            for (String tool : List.of("a", "b", "c")) {
                run.compare(target.exchange(toolCall(tool, "{}", "A")));
            }
        }

        assertThat(target.sent()).hasSize(9);
        assertThat(target.sent()).extracting(FakeMcpTarget::principal).containsExactly(
                "A", null, "B", "A", null, "B", "A", null, "B");
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT)
                .containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.REFUSED);
    }

    @Test
    void aRunStoppedMidItemPropagatesAndRecordsNothingForTheUnsentReplay() {
        FakeMcpTarget target = new FakeMcpTarget(request -> {
            if ("B".equals(FakeMcpTarget.principal(request))) {
                throw new AccessRunStopped("the server answered HTTP 429 Too Many Requests");
            }
            return "A".equals(FakeMcpTarget.principal(request)) ? FakeReply.result("owner note")
                    : FakeReply.unauthorized();
        });

        try (AccessComparisonRun run = check().begin(target.http())) {
            assertThatThrownBy(() -> run.compare(target.exchange(toolCall("a", "{}", "A"))))
                    .isInstanceOf(AccessRunStopped.class);
        }

        assertThat(ledger.outcomes()).doesNotContainKey("b");
    }

    @Test
    void anonymousReceivingTheOwnersResultSkipsTheIdentityReplays() {
        FakeMcpTarget target = new FakeMcpTarget(request -> FakeReply.result("public note"));

        compareOnce(target, toolCall("a", "{}", "A"));

        assertThat(target.sent()).extracting(FakeMcpTarget::principal).containsExactly("A", null);
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.NOT_RUN)
                .containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.SAME_RESULT);
    }

    @Test
    void unusableOwnerReplySkipsTheIdentityReplaysButStillCallsWithoutCredentials() {
        FakeMcpTarget target = new FakeMcpTarget(request -> FakeReply.toolError("broken"));

        compareOnce(target, toolCall("a", "{}", "A"));

        assertThat(target.sent()).hasSize(2);
        assertThat(target.sent().get(1).headerValue("Authorization")).isNull();
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.NOT_RUN)
                .containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.REFUSED);
    }

    @Test
    void unansweredAnonymousRequestRecordsAnErrorAndSkipsTheIdentityReplays() {
        FakeMcpTarget target = new FakeMcpTarget(request -> principal(request) == null
                ? new FakeReply(429, "", Map.of()) : FakeReply.result("note"));

        compareOnce(target, toolCall("a", "{}", "A"));

        assertThat(target.sent()).extracting(FakeMcpTarget::principal).containsExactly("A", null);
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.NOT_RUN)
                .containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.ERROR);
    }

    @Test
    void identityRefusedOrServedADifferentResultIsRecordedSo() {
        CallerServer server = CallerServer.stateless(caller -> "A".equals(caller) ? FakeReply.result("alice note")
                : FakeReply.result("notes of " + caller));
        FakeMcpTarget target = new FakeMcpTarget(server);
        compared.add(ComparisonHarness.peer("D"));
        server.refuse("D");

        compareOnce(target, toolCall("a", "{}", "A"));

        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.DIFFERENT_RESULT)
                .containsEntry("d", AccessOutcome.REFUSED)
                .containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.REFUSED);
    }

    @Test
    void ownersPrivateMarkerInAnIdentitysReplyFilesOneHighFirmIssueAndAnObjectLevelFinding() {
        owner = ComparisonHarness.owner(Optional.of(MARKER));
        FakeMcpTarget target = new FakeMcpTarget(CallerServer.stateless(caller -> FakeReply.result(MARKER + " note")));

        List<AuditIssue> issues = compareOnce(target, toolCall("get_note", "{}", "A"));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP operation result available to another principal");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.requestResponses()).hasSize(3);
        });
        assertThat(ledger.findingsOf("b")).containsExactly(new AccessFinding(AccessFinding.Kind.OBJECT_LEVEL,
                "Object-level: identity-B received Primary's private marker"));
    }

    @Test
    void identicalResultWithoutAPrivateMarkerIsOnlyASameResult() {
        FakeMcpTarget target = new FakeMcpTarget(CallerServer.stateless(caller -> FakeReply.result("shared note")));

        List<AuditIssue> issues = compareOnce(target, toolCall("get_note", "{}", "A"));

        assertThat(issues).isEmpty();
        assertThat(ledger.findings()).isEmpty();
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT);
    }

    @Test
    void identitySharingTheOwnersCredentialsIsNeverReplayedAndLoggedOncePerRun() {
        compared.add(SAME_AS_OWNER);
        FakeMcpTarget target = new FakeMcpTarget(CallerServer.stateless(caller -> FakeReply.result("note")));

        try (AccessComparisonRun run = check().begin(target.http())) {
            run.compare(target.exchange(toolCall("a", "{}", "A")));
            run.compare(target.exchange(toolCall("b", "{}", "A")));
        }

        assertThat(target.sent()).noneMatch(request -> "c".equals(request.headerValue(ScannerSentinels.IDENTITY_HEADER)));
        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .filteredOn(message -> message.contains("same credentials"))
                .containsExactly("Check access: identity-C has the same credentials as Primary — not compared");
    }

    @Test
    void comparedUserDuplicatingAnEarlierComparedUserIsNeitherReplayedNorReportedAndLoggedOncePerRun() {
        owner = ComparisonHarness.owner(Optional.of(MARKER));
        compared.add(new Principal("b2", "identity-B2", PrincipalRole.PEER,
                () -> Map.of("Authorization", "Bearer B"), Optional.empty(), Map.of()));
        FakeMcpTarget target = new FakeMcpTarget(CallerServer.stateless(caller -> FakeReply.result(MARKER + " note")));
        List<AuditIssue> issues = new ArrayList<>();

        try (AccessComparisonRun run = check().begin(target.http())) {
            issues.addAll(run.compare(target.exchange(toolCall("get_note", "{}", "A"))));
            run.compare(target.exchange(toolCall("other_note", "{}", "A")));
        }

        assertThat(issues).hasSize(1);
        assertThat(target.sent()).noneMatch(request -> "b2".equals(request.headerValue(ScannerSentinels.IDENTITY_HEADER)));
        assertThat(ledger.outcomes()).doesNotContainKey("b2");
        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                .filteredOn(message -> message.contains("same credentials"))
                .containsExactly("Check access: identity-B2 has the same credentials as identity-B — not compared");
    }

    @Test
    void statefulServerGetsOneHandshakePerIdentityPerRunWhateverTheItemCount() {
        CallerServer server = CallerServer.stateful(caller -> FakeReply.result("note"));
        FakeMcpTarget target = new FakeMcpTarget(server);

        try (AccessComparisonRun run = check().begin(target.http())) {
            for (String tool : List.of("a", "b", "c", "d")) {
                run.compare(target.exchange(liveToolCall(tool)));
            }
        }

        assertThat(target.sent()).filteredOn(request -> "initialize".equals(method(request)))
                .extracting(FakeMcpTarget::principal).containsExactlyInAnyOrder("B", null);
        assertThat(target.sent()).filteredOn(request -> "tools/call".equals(method(request))).hasSize(12);
        assertThat(target.sent()).filteredOn(request -> principal(request) == null)
                .noneMatch(request -> LIVE_SESSION.equals(session(request)));
        assertThat(target.sent()).filteredOn(request -> "tools/call".equals(method(request)))
                .filteredOn(request -> session(request) != null && !LIVE_SESSION.equals(session(request)))
                .allSatisfy(request -> assertThat(server.issuedTo(session(request))).isEqualTo(principal(request)));
    }

    @Test
    void refusedHandshakeIsReusedForLaterItemsWithoutResending() {
        CallerServer server = CallerServer.stateful(caller -> FakeReply.result("note"));
        server.refuse("B");
        FakeMcpTarget target = new FakeMcpTarget(server);

        try (AccessComparisonRun run = check().begin(target.http())) {
            run.compare(target.exchange(liveToolCall("a")));
            run.compare(target.exchange(liveToolCall("b")));
        }

        assertThat(target.sent()).filteredOn(request -> "B".equals(principal(request))).hasSize(1);
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.REFUSED);
    }

    @Test
    void aTransientHandshakeFailureIsRetriedOnTheNextItem() {
        CallerServer server = CallerServer.stateful(caller -> FakeReply.result("note"));
        int[] peerHandshakes = {0};
        FakeMcpTarget target = new FakeMcpTarget(request -> {
            boolean peerInitialize = "B".equals(principal(request))
                    && "initialize".equals(FakeMcpTarget.method(request));
            if (peerInitialize && peerHandshakes[0]++ == 0) {
                return new FakeReply(503, "", Map.of());
            }
            return server.apply(request);
        });

        try (AccessComparisonRun run = check().begin(target.http())) {
            run.compare(target.exchange(liveToolCall("a")));
            run.compare(target.exchange(liveToolCall("b")));
        }

        assertThat(peerHandshakes[0]).isEqualTo(2);
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT);
    }

    @Test
    void closingTheRunDeletesEverySessionItOpenedButNeverTheLiveOne() {
        CallerServer server = CallerServer.stateful(caller -> FakeReply.result("note"));
        FakeMcpTarget target = new FakeMcpTarget(server);

        try (AccessComparisonRun run = check().begin(target.http())) {
            run.compare(target.exchange(liveToolCall("a")));
            run.compare(target.exchange(liveToolCall("b")));
        }

        assertThat(target.sent()).filteredOn(request -> "DELETE".equals(request.method()))
                .extracting(FakeMcpTarget::session).containsExactlyInAnyOrderElementsOf(server.issued())
                .doesNotContain(LIVE_SESSION).isNotEmpty();
    }

    @Test
    void concurrentItemsShareOneHandshakePerIdentity() {
        CallerServer server = CallerServer.stateful(caller -> FakeReply.result("note"));
        FakeMcpTarget target = new FakeMcpTarget(server);
        ExecutorService pool = Executors.newFixedThreadPool(4);

        try (AccessComparisonRun run = check(CrossIdentityPorts.of(AccessLedger.noop(), PrincipalListings.unknown()))
                .begin(target.http())) {
            List<CompletableFuture<List<AuditIssue>>> items = List.of("a", "b", "c", "d", "e", "f", "g", "h").stream()
                    .map(tool -> CompletableFuture.supplyAsync(
                            () -> run.compare(target.exchange(liveToolCall(tool))), pool))
                    .toList();
            doneWithin(CompletableFuture.allOf(items.toArray(CompletableFuture[]::new)), Duration.ofSeconds(5));
        } finally {
            pool.shutdownNow();
        }

        assertThat(target.sent()).filteredOn(request -> "initialize".equals(method(request))).hasSize(2);
    }

    @Test
    void comparingWithAPoolSendsEveryComparedIdentitysReplayAtTheSameTime() {
        compared.add(ComparisonHarness.peer("D"));
        CountDownLatch bothReplaying = new CountDownLatch(2);
        AtomicInteger metTheOther = new AtomicInteger();
        FakeMcpTarget target = new FakeMcpTarget(replaysMeeting(bothReplaying, metTheOther));
        ExecutorService pool = Executors.newFixedThreadPool(2);

        try (AccessComparisonRun run = check().begin(target.http())) {
            run.compare(target.exchange(toolCall("a", "{}", "A")), pool);
        } finally {
            pool.shutdownNow();
        }

        assertThat(metTheOther).hasValue(2);
        assertThat(ledger.outcomes()).containsEntry("b", AccessOutcome.DIFFERENT_RESULT)
                .containsEntry("d", AccessOutcome.DIFFERENT_RESULT);
    }

    @Test
    void comparingWithoutAPoolSendsOneComparedIdentitysReplayAtATime() {
        compared.add(ComparisonHarness.peer("D"));
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger mostInFlight = new AtomicInteger();
        CallerServer server = CallerServer.stateless(caller -> FakeReply.result("note of " + caller));
        FakeMcpTarget target = new FakeMcpTarget(request -> {
            mostInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            try {
                return server.apply(request);
            } finally {
                inFlight.decrementAndGet();
            }
        });

        compareOnce(target, toolCall("a", "{}", "A"));

        assertThat(mostInFlight).hasValue(1);
        assertThat(target.sent()).extracting(FakeMcpTarget::principal).containsExactly("A", null, "B", "D");
    }

    private static Function<HttpRequest, FakeReply> replaysMeeting(CountDownLatch bothReplaying,
                                                                 AtomicInteger metTheOther) {
        CallerServer server = CallerServer.stateless(caller -> FakeReply.result("note of " + caller));
        return request -> {
            if (Set.of("B", "D").contains(String.valueOf(principal(request)))) {
                bothReplaying.countDown();
                if (awaited(bothReplaying)) {
                    metTheOther.incrementAndGet();
                }
            }
            return server.apply(request);
        };
    }

    private static boolean awaited(CountDownLatch latch) {
        try {
            return latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private List<AuditIssue> compareOnce(FakeMcpTarget target, HttpRequest ownerRequest) {
        try (AccessComparisonRun run = check().begin(target.http())) {
            return run.compare(target.exchange(ownerRequest));
        }
    }

    private static HttpRequest liveToolCall(String tool) {
        return toolCall(tool, "{}", "A").withAddedHeader("Mcp-Session-Id", LIVE_SESSION);
    }

    private CrossIdentityComparison check() {
        return check(CrossIdentityPorts.of(ledger, ledger));
    }

    private CrossIdentityComparison check(CrossIdentityPorts ports) {
        return new CrossIdentityComparison(eventLog, () -> new BearerTokenAuthStrategy("A"),
                () -> PrincipalRoster.of(owner, compared), ports);
    }
}
