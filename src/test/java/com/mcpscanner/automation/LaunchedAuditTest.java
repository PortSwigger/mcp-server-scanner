package com.mcpscanner.automation;

import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;
import com.mcpscanner.scan.BurpAuditRun;
import com.mcpscanner.scan.RunningScan;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LaunchedAuditTest {

    private final SiteMap siteMap = mock(SiteMap.class);
    private final CheckTelemetry telemetry = mock(CheckTelemetry.class);
    private final LaunchedAudit launched = new LaunchedAudit(siteMap, telemetry, () -> 24000);

    @Test
    void staysUnfinishedUntilEveryCollaboratorProbeHasSettled() {
        java.util.concurrent.atomic.AtomicBoolean settled = new java.util.concurrent.atomic.AtomicBoolean();
        LaunchedAudit watching = new LaunchedAudit(siteMap, telemetry, () -> 0, settled::get);
        Audit audit = mock(Audit.class);
        when(audit.statusMessage()).thenReturn("finished");
        watching.start(() -> new BurpAuditRun(audit));

        String whileWatching = watching.snapshot().orElseThrow().status();
        settled.set(true);

        assertThat(whileWatching).isEqualTo("awaiting Collaborator interactions");
        assertThat(watching.snapshot().orElseThrow().status()).isEqualTo("finished");
    }

    @Test
    void hasNoSnapshotBeforeAnAuditIsLaunched() {
        assertThat(launched.snapshot()).isEmpty();
    }

    @Test
    void snapshotsTheAuditCountersAndMarksWhichSiteMapIssuesAnExtensionRaised() {
        Audit audit = mock(Audit.class);
        when(audit.statusMessage()).thenReturn("finished");
        when(audit.requestCount()).thenReturn(120);
        when(audit.errorCount()).thenReturn(3);
        when(audit.insertionPointCount()).thenReturn(9);
        List<AuditIssue> issues = List.of(
                issue("MCP arbitrary host file read", ReportedIssue.EXTENSION_GENERATED_TYPE_INDEX),
                issue("File path traversal", 0x00100300));
        when(siteMap.issues()).thenReturn(issues);

        when(telemetry.sent()).thenReturn(40);
        when(telemetry.reached()).thenReturn(38);

        launched.start(() -> new BurpAuditRun(audit));

        AuditSnapshot snapshot = launched.snapshot().orElseThrow();
        assertThat(snapshot.status()).isEqualTo("finished");
        assertThat(snapshot.requestCount()).isEqualTo(120);
        assertThat(snapshot.errorCount()).isEqualTo(3);
        assertThat(snapshot.insertionPointCount()).isEqualTo(9);
        assertThat(snapshot.extensionRequestsSent()).isEqualTo(40);
        assertThat(snapshot.extensionRequestsReached()).isEqualTo(38);
        assertThat(snapshot.builtInRequestsDiverted()).isEqualTo(24000);
        assertThat(snapshot.issues()).extracting(ReportedIssue::name, ReportedIssue::extensionGenerated)
                .containsExactly(tuple("MCP arbitrary host file read", true),
                        tuple("File path traversal", false));
    }

    @Test
    void namesTheCheckBehindEachExtensionIssueAndTalliesProbesPerCheck() {
        Audit audit = mock(Audit.class);
        List<AuditIssue> issues = List.of(
                issue("MCP arbitrary host file read", ReportedIssue.EXTENSION_GENERATED_TYPE_INDEX),
                issue("File path traversal", 0x00100300));
        when(siteMap.issues()).thenReturn(issues);
        when(telemetry.checksReporting("MCP arbitrary host file read")).thenReturn(List.of("file-traversal"));
        when(telemetry.checksReporting("File path traversal")).thenReturn(List.of("file-traversal"));
        when(telemetry.probesByCheck()).thenReturn(Map.of("file-traversal", new CheckProbes(40, 38)));

        launched.start(() -> new BurpAuditRun(audit));

        AuditSnapshot snapshot = launched.snapshot().orElseThrow();
        assertThat(snapshot.issues()).extracting(ReportedIssue::name, ReportedIssue::checks)
                .containsExactly(tuple("MCP arbitrary host file read", List.of("file-traversal")),
                        tuple("File path traversal", List.of()));
        assertThat(snapshot.probesByCheck()).containsEntry("file-traversal", new CheckProbes(40, 38));
    }

    @Test
    void forgetsExtensionTrafficSentBeforeTheAuditStarts() {
        launched.start(() -> new BurpAuditRun(mock(Audit.class)));

        verify(telemetry).reset();
    }

    @Test
    void refusesARunThatIsNotABurpAuditBecauseItsSnapshotReadsBurpAuditCounters() {
        assertThatThrownBy(() -> launched.start(() -> mock(RunningScan.class)))
                .isInstanceOf(IllegalStateException.class);
        assertThat(launched.snapshot()).isEmpty();
    }

    private static AuditIssue issue(String name, int typeIndex) {
        AuditIssue issue = mock(AuditIssue.class, RETURNS_DEEP_STUBS);
        when(issue.name()).thenReturn(name);
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.FIRM);
        when(issue.definition().typeIndex()).thenReturn(typeIndex);
        when(issue.requestResponses()).thenReturn(List.of());
        return issue;
    }
}
