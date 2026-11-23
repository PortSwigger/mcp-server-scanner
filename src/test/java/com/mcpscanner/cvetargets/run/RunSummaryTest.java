package com.mcpscanner.cvetargets.run;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.cvetargets.manifest.ArmRole;
import com.mcpscanner.cvetargets.manifest.ExpectedOutcome;
import com.mcpscanner.cvetargets.manifest.Outcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RunSummaryTest {

    @TempDir
    Path root;

    @Test
    void listsEveryArmWithItsVerdictDurationOtherCheckIssuesAndWhyItCouldNotRun() throws IOException {
        IssueSummary outbound = new IssueSummary("MCP outbound request", AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.FIRM, "http://127.0.0.1:1", "detail");
        ArmResult judged = new ArmResult("check-b", "target-two", "fixed", "burp", ArmRole.FIXED, "1.0.1",
                ExpectedOutcome.of(Outcome.SILENT), Outcome.SILENT, true, "expected SILENT", List.of(), 3, 0,
                new ProbeTally(4, 4), 10, "2026-11-09T00:00:00Z", null, null, null, null, null, null,
                Map.of("check-a", List.of(outbound)), null);
        ArmResult refused = new ArmResult("check-a", "target-one", "vulnerable", "burp", ArmRole.VULNERABLE, "1.0.0",
                ExpectedOutcome.of(Outcome.FIRE), null, false, "not runnable: no OAuth", List.of(), 0, 0,
                ProbeTally.NONE, 0, null, null, null, null, null, null, null, Map.of(), "no OAuth");

        Path file = new RunSummary(root).write(List.of(judged, refused));

        JsonNode arms = new ObjectMapper().readTree(file.toFile()).path("arms");
        assertThat(file).isEqualTo(root.resolve("summary.json"));
        assertThat(arms).hasSize(2);
        assertThat(arms.get(0).path("check").asText()).isEqualTo("check-a");
        assertThat(arms.get(0).path("notRunnable").asText()).isEqualTo("no OAuth");
        assertThat(arms.get(0).path("passed").asBoolean()).isFalse();
        assertThat(arms.get(1).path("target").asText()).isEqualTo("target-two");
        assertThat(arms.get(1).path("arm").asText()).isEqualTo("fixed");
        assertThat(arms.get(1).path("expected").asText()).isEqualTo("SILENT");
        assertThat(arms.get(1).path("observed").asText()).isEqualTo("SILENT");
        assertThat(arms.get(1).path("passed").asBoolean()).isTrue();
        assertThat(arms.get(1).path("otherCheckIssues").path("check-a").get(0).asText())
                .isEqualTo("MCP outbound request");
        assertThat(arms.get(1).path("durationMillis").asLong()).isEqualTo(10);
        assertThat(arms.get(1).path("result").asText()).isEqualTo("check-b/target-two/fixed.json");
    }
}
