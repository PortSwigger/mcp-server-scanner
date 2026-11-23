package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.AuditResult;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.http.RequestTally;
import com.mcpscanner.logging.Counted;
import com.mcpscanner.logging.McpEventLog;

import java.util.function.Function;

public final class ScanCheckLogging {

    private ScanCheckLogging() {
    }

    static AuditResult runAndLog(McpEventLog eventLog, String checkId, Function<RequestTally, AuditResult> task) {
        logStarted(eventLog, checkId);
        long startNanos = System.nanoTime();
        RequestTally requests = RequestTally.started();
        try {
            AuditResult result = task.apply(requests);
            logFinish(eventLog, checkId, durationMillis(startNanos), requests.requests(), result.auditIssues().size());
            return result;
        } catch (RuntimeException e) {
            logError(eventLog, checkId, e);
            throw e;
        }
    }

    static void logLateIssues(McpEventLog eventLog, String checkId, int issueCount) {
        if (eventLog == null || issueCount == 0) {
            return;
        }
        eventLog.kept(CheckLog.prefix(checkId) + "reported " + Counted.of(issueCount, "issue")
                + " after its invocation finished, on a Collaborator interaction");
    }

    static void logIssuesAddedToSiteMapDirectly(McpEventLog eventLog, String checkId, int issueCount) {
        if (eventLog == null) {
            return;
        }
        eventLog.kept(CheckLog.prefix(checkId) + "Burp withheld a streamed reply during this run, so its "
                + Counted.of(issueCount, "issue") + (issueCount == 1 ? " was" : " were")
                + " added to the site map directly");
    }

    private static long durationMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private static void logStarted(McpEventLog eventLog, String checkId) {
        if (eventLog == null) {
            return;
        }
        eventLog.debug(CheckLog.prefix(checkId) + "started");
    }

    private static void logFinish(McpEventLog eventLog, String checkId, long durationMs, int requestCount,
                                  int issueCount) {
        if (eventLog == null) {
            return;
        }
        String message = CheckLog.prefix(checkId) + "finished in " + durationMs + "ms, "
                + Counted.of(requestCount, "request") + ", " + Counted.of(issueCount, "issue");
        if (issueCount > 0) {
            eventLog.kept(message);
        } else {
            eventLog.debug(message);
        }
    }

    static void logError(McpEventLog eventLog, String checkId, RuntimeException e) {
        if (eventLog == null) {
            return;
        }
        eventLog.error(CheckLog.prefix(checkId) + "threw " + e.getClass().getSimpleName()
                + ": " + e.getMessage(), e);
    }
}
