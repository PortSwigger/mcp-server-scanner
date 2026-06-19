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
    void emits_started_line_before_check_runs() {
        AuditResult empty = AuditResult.auditResult(List.of());

        ScanCheckLogging.runAndLog(eventLog, "demo-check", () -> empty);

        List<String> infos = infos();
        assertThat(infos).hasSize(2);
        assertThat(infos.get(0)).isEqualTo("Scan check: demo-check — started");
        assertThat(infos.get(1))
                .startsWith("Scan check: demo-check — finished in ")
                .endsWith("ms, 0 issues");
    }

    @Test
    void emits_decision_line_when_helper_called() {
        ScanCheckLogging.decisionSkipped(eventLog, "demo-check", "no bearer present");

        assertThat(infos()).containsExactly(
                "Scan check: demo-check — decision: skipped — no bearer present");
    }

    @Test
    void existing_finish_line_format_unchanged() {
        AuditResult oneIssue = AuditResult.auditResult(List.of());

        ScanCheckLogging.runAndLog(eventLog, "demo-check", () -> oneIssue);

        assertThat(infos().get(1))
                .matches("Scan check: demo-check — finished in \\d+ms, 0 issues");
    }

    @Test
    void decision_helper_is_null_event_log_safe() {
        ScanCheckLogging.decisionSkipped(null, "demo-check", "no bearer present");
    }

    private List<String> infos() {
        return eventLog.snapshot().stream()
                .filter(e -> e.level() == McpEventLog.Level.INFO)
                .map(McpEventLog.LogEntry::message)
                .toList();
    }
}
