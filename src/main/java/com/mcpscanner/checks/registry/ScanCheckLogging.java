package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.function.Supplier;

/**
 * Single seam for surfacing scan-check lifecycle events in the Logger tab.
 *
 * <p>Centralised here so every active and passive check emits identically-shaped lifecycle
 * lines without per-check duplication. Each invocation emits a {@code started} line before
 * the check runs and a {@code finished} line afterwards, so "ran with no findings" can be
 * told apart from "never ran" when diagnosing coverage gaps. Checks can also emit an
 * explicit {@code decision: skipped — <reason>} line via {@link #decisionSkipped} when they
 * short-circuit. Disabled checks emit nothing to avoid noise from toggle-driven traffic.
 */
public final class ScanCheckLogging {

    private ScanCheckLogging() {
    }

    static AuditResult runAndLog(McpEventLog eventLog, String checkId, Supplier<AuditResult> task) {
        return runLogging(eventLog, checkId, task, result -> result.auditIssues().size());
    }

    public static List<AuditIssue> runIssuesAndLog(McpEventLog eventLog, String checkId,
                                                   Supplier<List<AuditIssue>> task) {
        return runLogging(eventLog, checkId, task, List::size);
    }

    private static <T> T runLogging(McpEventLog eventLog, String checkId, Supplier<T> task,
                                    java.util.function.ToIntFunction<T> issueCount) {
        logStarted(eventLog, checkId);
        long startNanos = System.nanoTime();
        try {
            T result = task.get();
            logFinish(eventLog, checkId, durationMillis(startNanos), issueCount.applyAsInt(result));
            return result;
        } catch (RuntimeException e) {
            logError(eventLog, checkId, e);
            throw e;
        }
    }

    public static void decisionSkipped(McpEventLog eventLog, String checkId, String reason) {
        if (eventLog == null) {
            return;
        }
        eventLog.info("Scan check: " + checkId + " — decision: skipped — " + reason);
    }

    private static long durationMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private static void logStarted(McpEventLog eventLog, String checkId) {
        if (eventLog == null) {
            return;
        }
        eventLog.info("Scan check: " + checkId + " — started");
    }

    private static void logFinish(McpEventLog eventLog, String checkId, long durationMs, int issueCount) {
        if (eventLog == null) {
            return;
        }
        String suffix = issueCount == 1 ? " issue" : " issues";
        eventLog.info("Scan check: " + checkId + " — finished in " + durationMs + "ms, "
                + issueCount + suffix);
    }

    private static void logError(McpEventLog eventLog, String checkId, RuntimeException e) {
        if (eventLog == null) {
            return;
        }
        eventLog.error("Scan check: " + checkId + " — threw " + e.getClass().getSimpleName()
                + ": " + e.getMessage(), e);
    }
}
