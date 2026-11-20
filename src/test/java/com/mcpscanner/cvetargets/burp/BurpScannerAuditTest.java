package com.mcpscanner.cvetargets.burp;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.automation.AuditSnapshot;
import com.mcpscanner.automation.CheckAccessCommand;
import com.mcpscanner.automation.CheckAccessStatus;
import com.mcpscanner.automation.CheckProbes;
import com.mcpscanner.automation.LaunchedScan;
import com.mcpscanner.automation.ReportedIssue;
import com.mcpscanner.automation.ScanAllCommand;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.environment.Pause;
import com.mcpscanner.cvetargets.requests.ArmEndpoint;
import com.mcpscanner.cvetargets.run.ArmBoundAuth;
import com.mcpscanner.cvetargets.run.ArmObservation;
import com.mcpscanner.cvetargets.run.ArmProgress;
import com.mcpscanner.cvetargets.run.ArmProgressReport;
import com.mcpscanner.cvetargets.run.ArmRun;
import com.mcpscanner.cvetargets.run.ArmTeardown;
import com.mcpscanner.cvetargets.run.CheckFindings;
import com.mcpscanner.cvetargets.run.IssueSummary;
import com.mcpscanner.cvetargets.run.ProbeTally;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

class BurpScannerAuditTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:41000/mcp");
    private static final ReportedIssue OURS = new ReportedIssue("MCP arbitrary host file read", "HIGH", "FIRM",
            "http://127.0.0.1:41000", "detail", true, List.of(BurpArmFixtures.CHECK));
    private static final ReportedIssue BUILT_IN = new ReportedIssue("File path traversal", "HIGH", "FIRM",
            "http://127.0.0.1:41000", "detail", false, List.of());

    @TempDir
    Path root;

    private final List<ScanAllCommand> commands = new ArrayList<>();
    private boolean closed;
    private boolean launched;
    private String catalogLimit;
    private AuditSnapshot beforeLaunch;
    private AuditSnapshot finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(OURS, BUILT_IN), 0, Map.of());

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void judgesOnlyTheIssuesTheExtensionRaised() {
        ArmObservation observation = audit(BurpAuditConfiguration.EXTENSIONS_ONLY);

        assertThat(observation.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo("MCP arbitrary host file read");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        });
        assertThat(observation.baseRequestCount()).isEqualTo(19);
        assertThat(observation.probes()).isEqualTo(new ProbeTally(60, 57));
        assertThat(commands).singleElement().satisfies(command ->
                assertThat(command.checks()).containsExactly(BurpArmFixtures.CHECK));
        assertThat(closed).isTrue();
    }

    @Test
    void ignoresIssuesAnEarlierArmLeftInAReusedBurpsSiteMap() {
        ReportedIssue earlierBuiltIn = new ReportedIssue("Unencrypted communications", "LOW", "CERTAIN",
                "http://127.0.0.1:41001", "detail", false, List.of());
        beforeLaunch = new AuditSnapshot("finished", 400, 0, 12, 0, 0, List.of(earlierBuiltIn), 0, Map.of());
        finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(OURS, BUILT_IN, earlierBuiltIn), 0, Map.of());

        ArmObservation observation = audit(BurpAuditConfiguration.WITH_BUILTINS);

        assertThat(observation.issues()).singleElement().satisfies(issue ->
                assertThat(issue.name()).isEqualTo("MCP arbitrary host file read"));
        assertThat(((BurpAuditDetails) observation.auditDetails()).builtInIssues()).containsExactly(BUILT_IN);
    }

    @Test
    void judgesTheArmsOwnIssuesWhateverOriginTheyName() {
        ReportedIssue reportedOnTheIssuer = new ReportedIssue("OAuth redirect policy", "MEDIUM", "FIRM",
                "http://localhost:47321/authorize", "detail", true, List.of(BurpArmFixtures.CHECK));
        finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(OURS, reportedOnTheIssuer), 0, Map.of());

        assertThat(audit(BurpAuditConfiguration.EXTENSIONS_ONLY).issues()).hasSize(2);
    }

    @Test
    void asksForABurpThatHasNotScannedTheArmsOrigin() {
        List<String> origins = new ArrayList<>();
        new BurpScannerAudit((label, origin, abandoned) -> {
            origins.add(origin);
            return session();
        }, new ScanAllCommands(false, BurpAuditConfiguration.EXTENSIONS_ONLY),
                new AuditCompletion(Pause.sleeping(), Clock.systemUTC(), Duration.ZERO, Duration.ofMinutes(1)),
                BurpAuditConfiguration.EXTENSIONS_ONLY, Duration.ofHours(2), Clock.systemUTC())
                .audit(BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy()),
                        new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP), new ArmTeardown(), new ArmProgress());

        assertThat(origins).containsExactly("http://127.0.0.1:41000");
    }

    @Test
    void attributesEachExtensionIssueAndProbeToTheCheckThatRaisedIt() {
        ReportedIssue another = new ReportedIssue("MCP outbound request", "MEDIUM", "FIRM",
                "http://127.0.0.1:41000", "detail", true, List.of("another-check"));
        ReportedIssue unattributed = new ReportedIssue("Shared name", "LOW", "FIRM",
                "http://127.0.0.1:41000", "detail", true, List.of());
        finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(OURS, another, unattributed, BUILT_IN),
                0, Map.of(BurpArmFixtures.CHECK, new CheckProbes(40, 38), "another-check", new CheckProbes(20, 19)));

        ArmObservation observation = audit(BurpAuditConfiguration.EXTENSIONS_ONLY);

        assertThat(observation.of(BurpArmFixtures.CHECK).issues()).extracting(IssueSummary::name)
                .containsExactly("MCP arbitrary host file read");
        assertThat(observation.of(BurpArmFixtures.CHECK).probes()).isEqualTo(new ProbeTally(40, 38));
        assertThat(observation.issuesOtherThan(BurpArmFixtures.CHECK)).hasEntrySatisfying("another-check", issues ->
                assertThat(issues).extracting(IssueSummary::name).containsExactly("MCP outbound request"))
                .hasEntrySatisfying(CheckFindings.UNATTRIBUTED, issues ->
                        assertThat(issues).extracting(IssueSummary::name).containsExactly("Shared name"))
                .hasSize(2);
    }

    @Test
    void anIssueNameTwoChecksReportedIsUnattributedAndMayBeEitherChecks() {
        ReportedIssue shared = new ReportedIssue("Shared name", "LOW", "FIRM", "http://127.0.0.1:41000", "detail",
                true, List.of("another-check", BurpArmFixtures.CHECK));
        finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(shared), 0, Map.of());

        ArmObservation observation = audit(BurpAuditConfiguration.EXTENSIONS_ONLY);

        assertThat(observation.of(BurpArmFixtures.CHECK).issues()).isEmpty();
        assertThat(observation.ambiguousFor(BurpArmFixtures.CHECK)).extracting(IssueSummary::name)
                .containsExactly("Shared name");
        assertThat(observation.ambiguousFor("another-check")).extracting(IssueSummary::name)
                .containsExactly("Shared name");
        assertThat(observation.issuesOtherThan(BurpArmFixtures.CHECK)).containsOnlyKeys(CheckFindings.UNATTRIBUTED);
    }

    @Test
    void ignoresAnEarlierArmsIssueWhateverAttributionTheReusedBurpNowGivesIt() {
        ReportedIssue earlier = new ReportedIssue("Earlier finding", "HIGH", "FIRM", "http://127.0.0.1:41001",
                "detail", true, List.of("another-check"));
        beforeLaunch = new AuditSnapshot("finished", 400, 0, 12, 0, 0, List.of(earlier), 0, Map.of());
        finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(OURS, earlier.unattributed()), 0,
                Map.of());

        assertThat(audit(BurpAuditConfiguration.EXTENSIONS_ONLY).issues()).extracting(IssueSummary::name)
                .containsExactly("MCP arbitrary host file read");
    }

    @Test
    void runsAHarnessObtainedOAuthArm() {
        AuthStrategy oauth = mock(AuthStrategy.class, withSettings().extraInterfaces(ArmBoundAuth.class));

        assertThat(burpAudit(BurpAuditConfiguration.EXTENSIONS_ONLY).notRunnable(BurpArmFixtures.vulnerableArm(root, oauth)))
                .isEmpty();
    }

    @Test
    void extensionsOnlyCountsBuiltInIssuesWithoutRecordingThem() {
        BurpAuditDetails details = (BurpAuditDetails) audit(BurpAuditConfiguration.EXTENSIONS_ONLY).auditDetails();

        assertThat(details.configuration()).isEqualTo("extensions-only");
        assertThat(details.builtInIssueCount()).isEqualTo(1);
        assertThat(details.builtInIssues()).isEmpty();
        assertThat(details.end()).isEqualTo(CompletedAudit.AuditEnd.FINISHED);
        assertThat(details.requestCount()).isEqualTo(500);
        assertThat(details.insertionPointCount()).isEqualTo(12);
    }

    @Test
    void withBuiltinsRecordsBurpsOwnIssuesBesideTheJudgedOnes() {
        BurpAuditDetails details = (BurpAuditDetails) audit(BurpAuditConfiguration.WITH_BUILTINS).auditDetails();

        assertThat(details.configuration()).isEqualTo("with-builtins");
        assertThat(details.builtInIssues()).containsExactly(BUILT_IN);
    }

    @Test
    void closesBurpWhenTheAuditFails() {
        finalSnapshot = null;

        assertThatThrownBy(() -> audit(BurpAuditConfiguration.EXTENSIONS_ONLY))
                .isInstanceOf(IllegalStateException.class);
        assertThat(closed).isTrue();
    }

    @Test
    void anAuditThatStopsWithoutFinishingIsNotEvidence() {
        finalSnapshot = new AuditSnapshot("scanning", 500, 0, 12, 60, 57, List.of(), 0, Map.of());
        BurpScannerAudit quietAfterAnInstant = new BurpScannerAudit((label, origin, abandoned) -> session(), new ScanAllCommands(false, BurpAuditConfiguration.EXTENSIONS_ONLY),
                new AuditCompletion(Pause.sleeping(), Clock.systemUTC(), Duration.ZERO, Duration.ZERO),
                BurpAuditConfiguration.EXTENSIONS_ONLY, Duration.ofHours(2), Clock.systemUTC());

        assertThatThrownBy(() -> quietAfterAnInstant.audit(BurpArmFixtures.fixedArm(root, new NoAuthStrategy()),
                new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP), new ArmTeardown(), new ArmProgress()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("without finishing");
        assertThat(closed).isTrue();
    }

    @Test
    void aLegacySseArmWhoseIssueEvidenceAnswersAPostWithTheStreamFails() {
        String composite = "POST /messages?session_id=1 HTTP/1.1 => HTTP/1.1 200 OK | text/event-stream";
        finalSnapshot = new AuditSnapshot("finished", 500, 20, 12, 60, 57, List.of(new ReportedIssue(
                "MCP arbitrary host file read", "HIGH", "FIRM", "http://127.0.0.1:41000", "detail", true,
                List.of(BurpArmFixtures.CHECK), List.of(composite))), 0, Map.of());

        assertThatThrownBy(() -> burpAudit(BurpAuditConfiguration.EXTENSIONS_ONLY).audit(
                BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy()),
                new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.SSE), new ArmTeardown(),
                new ArmProgress())).isInstanceOf(IllegalStateException.class).hasMessageContaining(composite);
        assertThat(closed).isTrue();
    }

    @Test
    void anAuditThatStopsWithoutFinishingLeavesItsLastSnapshotAsProgress() {
        finalSnapshot = new AuditSnapshot("scanning", 500, 0, 12, 60, 57, List.of(OURS, BUILT_IN), 0, Map.of());
        BurpScannerAudit quietAfterAnInstant = new BurpScannerAudit((label, origin, abandoned) -> session(),
                new ScanAllCommands(false, BurpAuditConfiguration.EXTENSIONS_ONLY),
                new AuditCompletion(Pause.sleeping(), Clock.systemUTC(), Duration.ZERO, Duration.ZERO),
                BurpAuditConfiguration.EXTENSIONS_ONLY, Duration.ofHours(2), Clock.systemUTC());
        ArmProgress progress = new ArmProgress();

        assertThatThrownBy(() -> quietAfterAnInstant.audit(BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy()),
                new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP), new ArmTeardown(),
                progress)).isInstanceOf(IllegalStateException.class);

        assertThat(progress.latest()).hasValueSatisfying(observed -> {
            assertThat(observed.probes()).isEqualTo(new ProbeTally(60, 57));
            assertThat(observed.issues()).singleElement().satisfies(issue ->
                    assertThat(issue.name()).isEqualTo("MCP arbitrary host file read"));
            assertThat(((BurpAuditDetails) observed.auditDetails()).end())
                    .isEqualTo(CompletedAudit.AuditEnd.UNFINISHED);
        });
    }

    @Test
    void namesTheCatalogLimitWhenTheExtensionTrimmedTheScannedCatalog() {
        catalogLimit = "catalog limited to 100 items per kind (tools 124 -> 100); seed requests are still sent";
        List<String> lines = new java.util.ArrayList<>();

        burpAudit(BurpAuditConfiguration.EXTENSIONS_ONLY).audit(BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy()),
                new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP), new ArmTeardown(),
                new ArmProgress(new ArmProgressReport("arm", Clock.systemUTC(), Duration.ofHours(1), lines::add)));

        assertThat(lines).contains("cve-targets: arm: " + catalogLimit);
    }

    @Test
    void givesAnArmAtLeastTheBurpMinimumTime() {
        BurpScannerAudit audit = burpAudit(BurpAuditConfiguration.EXTENSIONS_ONLY);

        assertThat(audit.armTimeout(Duration.ofMinutes(20))).isEqualTo(Duration.ofHours(2));
        assertThat(audit.armTimeout(Duration.ofHours(3))).isEqualTo(Duration.ofHours(3));
    }

    @Test
    void reportsItsModeAsBurp() {
        assertThat(burpAudit(BurpAuditConfiguration.EXTENSIONS_ONLY).mode()).isEqualTo("burp");
    }

    private ArmObservation audit(BurpAuditConfiguration configuration) {
        ArmRun run = BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy());
        return burpAudit(configuration).audit(run,
                new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP), new ArmTeardown(), new ArmProgress());
    }

    private BurpScannerAudit burpAudit(BurpAuditConfiguration configuration) {
        return new BurpScannerAudit((label, origin, abandoned) -> session(), new ScanAllCommands(false, BurpAuditConfiguration.EXTENSIONS_ONLY),
                new AuditCompletion(Pause.sleeping(), Clock.systemUTC(), Duration.ZERO, Duration.ofMinutes(1)),
                configuration, Duration.ofHours(2), Clock.systemUTC());
    }

    private BurpSession session() {
        BurpAutomation automation = new BurpAutomation() {
            @Override
            public LaunchedScan scanAll(ScanAllCommand command) {
                commands.add(command);
                launched = true;
                return new LaunchedScan(19, catalogLimit);
            }

            @Override
            public Optional<AuditSnapshot> audit() {
                return Optional.ofNullable(launched ? finalSnapshot : beforeLaunch);
            }

            @Override
            public CheckAccessStatus checkAccess(CheckAccessCommand command) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Optional<CheckAccessStatus> checkAccessStatus() {
                return Optional.empty();
            }
        };
        return new BurpSession() {
            @Override
            public BurpAutomation automation() {
                return automation;
            }

            @Override
            public void close() {
                closed = true;
            }
        };
    }
}
