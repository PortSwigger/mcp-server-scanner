package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.AuditResult;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScanCheckLoggingTest {

    private McpEventLog eventLog;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        eventLog = new McpEventLog(null);
    }

    @Test
    void logs_the_started_and_issue_free_finish_lines_of_an_invocation_at_debug_only() {
        AuditResult empty = AuditResult.auditResult(List.of());

        ScanCheckLogging.runAndLog(eventLog, "demo-check", tally -> empty);

        assertThat(lines(McpEventLog.Level.INFO)).isEmpty();
        List<String> debugs = lines(McpEventLog.Level.DEBUG);
        assertThat(debugs).hasSize(2);
        assertThat(debugs.get(0)).isEqualTo("Scan check: demo-check — started");
        assertThat(debugs.get(1))
                .startsWith("Scan check: demo-check — finished in ")
                .endsWith("ms, 0 requests, 0 issues");
    }

    @Test
    void finish_line_counts_the_requests_the_invocation_sent() {
        ScanCheckLogging.runAndLog(eventLog, "demo-check", tally -> {
            tally.record();
            tally.record();
            return AuditResult.auditResult(List.of());
        });

        assertThat(lines(McpEventLog.Level.DEBUG).get(1))
                .matches("Scan check: demo-check — finished in \\d+ms, 2 requests, 0 issues");
    }

    @Test
    void a_thousand_issue_free_invocations_do_not_push_out_an_earlier_info_line() {
        eventLog.info("Connect: browser consent check found nothing");

        for (int invocation = 0; invocation < 1000; invocation++) {
            ScanCheckLogging.runAndLog(eventLog, "demo-check", tally -> AuditResult.auditResult(List.of()));
        }

        assertThat(lines(McpEventLog.Level.INFO)).containsExactly("Connect: browser consent check found nothing");
    }

    @Test
    void keeps_the_finish_line_of_an_invocation_that_reported_issues() {
        AuditResult oneIssue = AuditResult.auditResult(List.of(org.mockito.Mockito.mock(
                burp.api.montoya.scanner.audit.issues.AuditIssue.class)));

        ScanCheckLogging.runAndLog(eventLog, "demo-check", tally -> oneIssue);

        assertThat(eventLog.snapshot()).filteredOn(McpEventLog.LogEntry::kept)
                .extracting(McpEventLog.LogEntry::message).singleElement().asString().endsWith("ms, 0 requests, 1 issue");
    }

    @Test
    void does_not_keep_the_finish_line_of_an_invocation_without_issues() {
        ScanCheckLogging.runAndLog(eventLog, "demo-check", tally -> AuditResult.auditResult(List.of()));

        assertThat(eventLog.snapshot()).noneMatch(McpEventLog.LogEntry::kept);
    }

    private List<String> lines(McpEventLog.Level level) {
        return eventLog.snapshot().stream()
                .filter(e -> e.level() == level)
                .map(McpEventLog.LogEntry::message)
                .toList();
    }
}
