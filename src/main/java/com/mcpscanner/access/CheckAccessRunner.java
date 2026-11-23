package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.access.AccessComparison;
import com.mcpscanner.access.AccessRunStopped;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.RetryAfterHonouringHttp;
import com.mcpscanner.checks.api.RetryAfterWaits;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.CountingHttp;
import com.mcpscanner.http.ThreadTallies;
import com.mcpscanner.http.UpstreamEvidence;
import com.mcpscanner.http.evidence.ReportedEvidence;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.mcp.ToolHarm;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class CheckAccessRunner {

    private static final int SEQUENTIAL = 1;
    private static final List<ToolHarm> REPLAY_ORDER =
            List.of(ToolHarm.POSSIBLE_READ, ToolHarm.WRITE, ToolHarm.DESTRUCTIVE);

    private final AccessComparison comparison;
    private final Http http;
    private final OwnerRequests requests;
    private final Consumer<AuditIssue> issueSink;
    private final WriteReplays writeReplays;
    private final AccessRuns runs;
    private final McpEventLog eventLog;
    private final UpstreamEvidence upstreamEvidence;
    private final ReportedEvidence reportedEvidence = new ReportedEvidence(ScannerSentinels.ALL);
    private final Supplier<AccessSnapshot> results;
    private final PreComparisonDiscovery discovery;
    private final ListingAudit listingAudit;

    public CheckAccessRunner(AccessComparison comparison, Http http, OwnerRequests requests,
                             Consumer<AuditIssue> issueSink, WriteReplays writeReplays, AccessRuns runs,
                             McpEventLog eventLog) {
        this(comparison, http, requests, issueSink, writeReplays, runs, eventLog, CheckAccessOptions.DEFAULTS);
    }

    public CheckAccessRunner(AccessComparison comparison, Http http, OwnerRequests requests,
                             Consumer<AuditIssue> issueSink, WriteReplays writeReplays, AccessRuns runs,
                             McpEventLog eventLog, CheckAccessOptions options) {
        this.listingAudit = options.listingAudit();
        this.discovery = options.discovery();
        this.results = options.results();
        this.upstreamEvidence = new UpstreamEvidence(options.upstreamExchanges());
        this.comparison = comparison;
        this.http = http;
        this.requests = requests;
        this.issueSink = issueSink;
        this.writeReplays = writeReplays;
        this.runs = runs;
        this.eventLog = eventLog;
    }

    public Optional<AccessRun> start(List<AccessRow> rows, WriteReplayApproval approval, AccessRunListener listener) {
        List<AccessRow> writeRows = writeRows(rows);
        List<McpToolDefinition> writes = requests.ownersTools(writeRows);
        if (!writes.isEmpty() && !approval.approve(writes, requests.minedArguments(writeRows))) {
            eventLog.info("Check access cancelled at the write-tool confirmation");
            return Optional.empty();
        }
        writeReplays.confirm(writes);
        List<AccessRow> queued = List.copyOf(rows);
        return Optional.of(runs.start(run -> runSurvivingCrash(queued, run, listener)));
    }

    private void runSurvivingCrash(List<AccessRow> queued, AccessRun run, AccessRunListener listener) {
        try {
            runAll(queued, run, listener);
        } catch (RuntimeException crash) {
            eventLog.error("Check access failed: " + reasonOf(crash), crash);
            listener.finished(new AccessRunSummary(0, queued.size(), 0, run.cancelled(),
                    Optional.of("Check access failed: " + reasonOf(crash))));
        }
    }

    private void runAll(List<AccessRow> queued, AccessRun run, AccessRunListener listener) {
        eventLog.info("Check access started for " + queued.size() + " items");
        Set<AccessItemKey> knownBeforeDiscovery = itemKeys(results.get().rows());
        discovery.discoverMissing();
        List<AccessRow> rows = currentRows(queued, knownBeforeDiscovery);
        TooManyRequestsStop guarded = guarded(run);
        ThreadTallies perItem = new ThreadTallies();
        Http counted = CountingHttp.counting(new InFlightLimit(guarded), perItem);
        RepeatedFailure failures = new RepeatedFailure();
        RunTally tally = new RunTally(rows.size(), listener);
        try (AccessComparisonRun comparisons = comparison.begin(counted);
             IdentityWorkers identities = new IdentityWorkers()) {
            ItemCheck check = new ItemCheck(guarded, counted, comparisons, perItem);
            BiConsumer<AccessRow, RowOutcome> completed = (row, outcome) ->
                    tally.completed(outcome, stopReasonAfter(row, outcome, failures, guarded));
            BooleanSupplier continuing = () -> !run.cancelled() && !tally.stopped();
            ParallelItems.run(readRows(rows), check.comparingIdentitiesOn(perItem.carrying(identities.executor())),
                    completed, continuing);
            for (ToolHarm harm : REPLAY_ORDER) {
                ParallelItems.run(rowsOf(rows, harm), SEQUENTIAL, check.comparingIdentitiesOn(Runnable::run),
                        completed, continuing);
            }
        }
        boolean cancelled = run.cancelled() || Thread.currentThread().isInterrupted();
        if (!cancelled) {
            tally.raised(raiseListingIssues());
        }
        AccessRunSummary summary = tally.summary(cancelled);
        logEnd(summary, tally.stopReason());
        logUnconfirmedSameResults(rows);
        listener.finished(summary);
    }

    private int raiseListingIssues() {
        try {
            List<AuditIssue> issues = reportable(listingAudit.issues());
            issues.forEach(issueSink);
            return issues.size();
        } catch (RuntimeException failure) {
            eventLog.warn("Check access could not compare tool listings: " + reasonOf(failure));
            return 0;
        }
    }

    private List<AuditIssue> reportable(List<AuditIssue> issues) {
        return reportedEvidence.of(upstreamEvidence.translate(issues));
    }

    private List<AccessRow> currentRows(List<AccessRow> queued, Set<AccessItemKey> knownBeforeDiscovery) {
        List<AccessRow> current = results.get().rows();
        Map<AccessItemKey, AccessRow> byKey = current.stream()
                .collect(Collectors.toMap(row -> row.item().key(), Function.identity(), (first, second) -> first));
        Set<AccessItemKey> queuedKeys = itemKeys(queued);
        Stream<AccessRow> refreshed = queued.stream().map(row -> byKey.getOrDefault(row.item().key(), row));
        boolean wholeMatrixQueued = queuedKeys.containsAll(knownBeforeDiscovery);
        Stream<AccessRow> revealed = current.stream().filter(row -> wholeMatrixQueued)
                .filter(row -> !knownBeforeDiscovery.contains(row.item().key()))
                .filter(row -> !queuedKeys.contains(row.item().key()));
        return Stream.concat(refreshed, revealed).toList();
    }

    private static Set<AccessItemKey> itemKeys(List<AccessRow> rows) {
        return rows.stream().map(row -> row.item().key()).collect(Collectors.toSet());
    }

    private TooManyRequestsStop guarded(AccessRun run) {
        AtomicBoolean stopped = new AtomicBoolean();
        RetryAfterWaits waits = RetryAfterWaits.onAnyThread(() -> !run.cancelled() && !stopped.get());
        return new TooManyRequestsStop(new RetryAfterHonouringHttp(http, CheckLog.labelled(eventLog, "Check access"),
                new ScanNotices()::firstTime, waits), stopped);
    }

    private void logEnd(AccessRunSummary summary, Optional<String> stopReason) {
        String progress = summary.checked() + " of " + summary.total() + " items";
        stopReason.ifPresentOrElse(
                reason -> eventLog.warn("Check access stopped: " + reason + " (" + progress + " checked)"),
                () -> eventLog.info("Check access " + (summary.cancelled() ? "cancelled" : "finished") + ": "
                        + progress + ", " + summary.issues() + " issues"));
    }

    private void logUnconfirmedSameResults(List<AccessRow> checked) {
        Set<AccessItemKey> keys = checked.stream().map(row -> row.item().key()).collect(Collectors.toSet());
        List<String> names = results.get().unconfirmedSameResults().stream().map(row -> row.item().key())
                .filter(keys::contains).map(AccessItemKey::name).toList();
        if (!names.isEmpty()) {
            eventLog.info("Check access: a lower-privilege user gets the owner's result and who should reach it is "
                    + "only inferred; confirm Who should reach it for " + String.join(", ", names));
        }
    }

    private Optional<String> stopReasonAfter(AccessRow row, RowOutcome outcome, RepeatedFailure failures,
                                             TooManyRequestsStop guarded) {
        return guarded.reason().or(() -> repeatedFailure(row, outcome, failures));
    }

    private Optional<String> repeatedFailure(AccessRow row, RowOutcome outcome, RepeatedFailure failures) {
        Optional<String> repeated = failures.repeatedBy(outcome.transportFailure());
        if (repeated.isEmpty()) {
            outcome.transportFailure().ifPresent(reason -> warnFailed(row, reason));
        }
        return repeated;
    }

    private final class ItemCheck {

        private final TooManyRequestsStop guarded;
        private final Http counted;
        private final AccessComparisonRun comparisons;
        private final ThreadTallies perItem;

        ItemCheck(TooManyRequestsStop guarded, Http counted, AccessComparisonRun comparisons, ThreadTallies perItem) {
            this.guarded = guarded;
            this.counted = counted;
            this.comparisons = comparisons;
            this.perItem = perItem;
        }

        Function<AccessRow, RowOutcome> comparingIdentitiesOn(Executor identities) {
            return row -> perItem.measure("Check access " + row.item().key().name(), eventLog::debug,
                    () -> checkRow(row, this, identities));
        }
    }

    private RowOutcome checkRow(AccessRow row, ItemCheck check, Executor identities) {
        if (!writeReplays.permits(row.item().key())) {
            eventLog.info("Check access skipped " + row.item().key().name() + ": write replay is no longer confirmed");
            return RowOutcome.checked(0);
        }
        HttpRequestResponse base;
        try {
            base = check.counted.sendRequest(requests.forOwner(row));
        } catch (AccessRunStopped stopped) {
            return RowOutcome.checked(0);
        } catch (RuntimeException failure) {
            return RowOutcome.unreachable(reasonOf(failure));
        }
        return check.guarded.reason().isPresent() ? RowOutcome.checked(0)
                : compare(row, base, check.comparisons, identities);
    }

    private RowOutcome compare(AccessRow row, HttpRequestResponse base, AccessComparisonRun comparisons,
                               Executor identities) {
        try {
            List<AuditIssue> issues = reportable(comparisons.compare(base, identities));
            issues.forEach(issueSink);
            return RowOutcome.checked(issues.size());
        } catch (AccessRunStopped stopped) {
            return RowOutcome.checked(0);
        } catch (RuntimeException failure) {
            warnFailed(row, reasonOf(failure));
            return RowOutcome.checked(0);
        }
    }

    private void warnFailed(AccessRow row, String reason) {
        eventLog.warn("Check access failed for " + row.item().key().name() + ": " + reason);
    }

    private static String reasonOf(RuntimeException failure) {
        return Objects.requireNonNullElse(failure.getMessage(), failure.getClass().getSimpleName());
    }

    private static List<AccessRow> writeRows(List<AccessRow> rows) {
        return rows.stream().filter(row -> row.item().writes()).toList();
    }

    private static List<AccessRow> readRows(List<AccessRow> rows) {
        return rowsOf(rows, ToolHarm.READ);
    }

    private static List<AccessRow> rowsOf(List<AccessRow> rows, ToolHarm harm) {
        return rows.stream().filter(row -> row.item().harm() == harm).toList();
    }
}
