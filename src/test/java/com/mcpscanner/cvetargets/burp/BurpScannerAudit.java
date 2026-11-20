package com.mcpscanner.cvetargets.burp;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.automation.AuditSnapshot;
import com.mcpscanner.automation.CheckProbes;
import com.mcpscanner.automation.LaunchedScan;
import com.mcpscanner.automation.ReportedIssue;
import com.mcpscanner.cvetargets.requests.ArmEndpoint;
import com.mcpscanner.cvetargets.run.ArmAudit;
import com.mcpscanner.cvetargets.run.ArmObservation;
import com.mcpscanner.cvetargets.run.ArmProgress;
import com.mcpscanner.cvetargets.run.ArmRun;
import com.mcpscanner.cvetargets.run.ArmTeardown;
import com.mcpscanner.cvetargets.run.CheckFindings;
import com.mcpscanner.cvetargets.run.IssueSummary;
import com.mcpscanner.cvetargets.run.ProbeTally;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class BurpScannerAudit implements ArmAudit {

    private final BurpLauncher launcher;
    private final ScanAllCommands commands;
    private final AuditCompletion completion;
    private final BurpAuditConfiguration configuration;
    private final Duration minimumArmTimeout;
    private final Clock clock;

    BurpScannerAudit(BurpLauncher launcher, ScanAllCommands commands, AuditCompletion completion,
                     BurpAuditConfiguration configuration, Duration minimumArmTimeout, Clock clock) {
        this.minimumArmTimeout = minimumArmTimeout;
        this.launcher = launcher;
        this.commands = commands;
        this.completion = completion;
        this.configuration = configuration;
        this.clock = clock;
    }

    @Override
    public String mode() {
        return "burp";
    }

    @Override
    public ArmObservation audit(ArmRun run, ArmEndpoint endpoint, ArmTeardown teardown, ArmProgress progress) {
        Instant starting = clock.instant();
        ArmOrigin origin = ArmOrigin.of(endpoint.uri());
        try (BurpSession burp = launcher.start(BurpLauncher.labelFor(run), origin.value(), teardown::isClosed)) {
            Instant started = clock.instant();
            Set<ReportedIssue> earlierArms = reportedSoFar(burp.automation());
            LaunchedScan launched = RetriedScanAll.launch(burp.automation(), commands.forArm(run, endpoint));
            Optional.ofNullable(launched.catalogLimit()).ifPresent(progress::note);
            Duration startup = Duration.between(starting, started);
            CompletedAudit audit = requireFinished(completion.await(burp.automation(), teardown::isClosed,
                    snapshot -> progress.record(observation(launched, polled(snapshot), earlierArms, startup,
                            Duration.between(started, clock.instant())))));
            ArmObservation observation = observation(launched, audit, earlierArms, startup,
                    Duration.between(started, clock.instant()));
            LegacySseEvidenceShape.require(endpoint.transport(), observation.issues());
            return observation;
        }
    }

    @Override
    public Optional<String> notRunnable(ArmRun run) {
        return commands.notRunnable(run);
    }

    @Override
    public Duration armTimeout(Duration declared) {
        return declared.compareTo(minimumArmTimeout) >= 0 ? declared : minimumArmTimeout;
    }

    private static CompletedAudit requireFinished(CompletedAudit audit) {
        if (audit.end() != CompletedAudit.AuditEnd.FINISHED) {
            AuditSnapshot snapshot = audit.snapshot();
            throw new IllegalStateException("Burp's audit stopped sending without finishing (" + snapshot.status()
                    + ", " + snapshot.requestCount() + " requests), so it is not evidence either way");
        }
        return audit;
    }

    private static CompletedAudit polled(AuditSnapshot snapshot) {
        return new CompletedAudit(snapshot, AuditCompletion.FINISHED.equalsIgnoreCase(snapshot.status())
                ? CompletedAudit.AuditEnd.FINISHED : CompletedAudit.AuditEnd.UNFINISHED);
    }

    private static Set<ReportedIssue> reportedSoFar(BurpAutomation burp) {
        return burp.audit().map(snapshot -> snapshot.issues().stream().map(ReportedIssue::unattributed)
                .collect(Collectors.toUnmodifiableSet())).orElse(Set.of());
    }

    private ArmObservation observation(LaunchedScan launched, CompletedAudit audit, Set<ReportedIssue> earlierArms,
                                       Duration startup, Duration auditing) {
        AuditSnapshot snapshot = audit.snapshot();
        Map<Boolean, List<ReportedIssue>> byOrigin = snapshot.issues().stream()
                .filter(issue -> !earlierArms.contains(issue.unattributed()))
                .collect(Collectors.partitioningBy(ReportedIssue::extensionGenerated));
        List<ReportedIssue> builtIn = byOrigin.get(false);
        BurpAuditDetails details = new BurpAuditDetails(configuration.id(), snapshot.status(), audit.end(),
                launched.requests(), snapshot.requestCount(), snapshot.errorCount(), snapshot.insertionPointCount(),
                builtIn.size(), configuration.builtInIssuesToRecord(builtIn), startup.toMillis(), auditing.toMillis());
        List<ReportedIssue> extension = byOrigin.get(true);
        return new ArmObservation(extension.stream().map(BurpScannerAudit::summary).toList(), launched.requests(), 0,
                new ProbeTally(snapshot.extensionRequestsSent(), snapshot.extensionRequestsReached()), details,
                findingsByCheck(extension, snapshot.probesByCheck()));
    }

    private static Map<String, CheckFindings> findingsByCheck(List<ReportedIssue> issues,
                                                              Map<String, CheckProbes> probes) {
        Map<String, List<IssueSummary>> owned = issues.stream().collect(Collectors.groupingBy(
                BurpScannerAudit::owner, Collectors.mapping(BurpScannerAudit::summary, Collectors.toList())));
        Map<String, List<IssueSummary>> ambiguous = issues.stream().filter(issue -> issue.checks().size() > 1)
                .flatMap(issue -> issue.checks().stream().map(check -> Map.entry(check, summary(issue))))
                .collect(Collectors.groupingBy(Map.Entry::getKey,
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())));
        Set<String> checks = new HashSet<>(owned.keySet());
        checks.addAll(ambiguous.keySet());
        checks.addAll(probes.keySet());
        return checks.stream().collect(Collectors.toMap(Function.identity(), check -> new CheckFindings(
                owned.getOrDefault(check, List.of()), tally(probes.get(check)),
                ambiguous.getOrDefault(check, List.of()))));
    }

    private static String owner(ReportedIssue issue) {
        return issue.checks().size() == 1 ? issue.checks().get(0) : CheckFindings.UNATTRIBUTED;
    }

    private static ProbeTally tally(CheckProbes probes) {
        return probes == null ? ProbeTally.NONE : new ProbeTally(probes.sent(), probes.reached());
    }

    static IssueSummary summary(ReportedIssue issue) {
        return new IssueSummary(issue.name(), AuditIssueSeverity.valueOf(issue.severity()),
                AuditIssueConfidence.valueOf(issue.confidence()), issue.baseUrl(), issue.detail(), issue.evidence());
    }
}
