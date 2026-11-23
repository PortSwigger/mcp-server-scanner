package com.mcpscanner.cvetargets;

import com.mcpscanner.cvetargets.access.CheckAccessSubject;
import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.cvetargets.environment.FileRecorderUsers;
import com.mcpscanner.cvetargets.environment.InteractionRecorder;
import com.mcpscanner.cvetargets.environment.ProcessCommandRunner;
import com.mcpscanner.cvetargets.identities.ArmIdentities;
import com.mcpscanner.cvetargets.identities.IdentityScripts;
import com.mcpscanner.cvetargets.environment.RecorderIdentity;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.TargetArm;
import com.mcpscanner.cvetargets.manifest.TargetRepository;
import com.mcpscanner.cvetargets.outofband.LazyRecorderCollaborator;
import com.mcpscanner.cvetargets.run.ArmContexts;
import com.mcpscanner.cvetargets.run.ArmDurations;
import com.mcpscanner.cvetargets.run.ArmResult;
import com.mcpscanner.cvetargets.run.ArmRun;
import com.mcpscanner.cvetargets.run.ArmSchedule;
import com.mcpscanner.cvetargets.run.AuditedArm;
import com.mcpscanner.cvetargets.run.CveTargetHarness;
import com.mcpscanner.cvetargets.run.HarnessSettings;
import com.mcpscanner.cvetargets.run.RunSummary;
import com.mcpscanner.cvetargets.shared.SharedArmPlanner;
import com.mcpscanner.cvetargets.shared.SharedTargetArms;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@Tag("cve-target")
@DisabledIfSystemProperty(named = AccessMiningMeasurementTest.MINE_PROPERTY, matches = "true")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CveTargetSuiteTest implements ArmContexts {

    private final HarnessSettings settings = HarnessSettings.fromSystemProperties();
    private final CveTargetHarness harness = HarnessMode.fromSystemProperties().harness(settings);
    private final IdentityScripts identityScripts = IdentityScripts.processes();
    private final LazyRecorderCollaborator collaborator = new LazyRecorderCollaborator(new InteractionRecorder(
            new ProcessCommandRunner(), settings.targetsRoot().resolve("_shared/interaction-recorder"),
            RecorderIdentity.SHARED, new FileRecorderUsers(settings.recorderLocksDirectory()), System.err::println));
    private final ArmSchedule schedule = new ArmSchedule(settings.parallelArms());
    private final ScheduledArmTests scheduled = new ScheduledArmTests(schedule,
            new ArmDurations(settings.durationsFile(), System.err::println));

    @BeforeAll
    void startTheInteractionRecorderBeforeTargetsResolveNames() {
        collaborator.start();
    }

    @AfterAll
    void summariseAndStopScheduling() {
        new RunSummary(settings.resultsRoot()).write(scheduled.completedResults());
        schedule.close();
    }

    @TestFactory
    List<DynamicNode> everySelectedTargetMeetsItsDeclaredOutcomePerArm() {
        List<LoadedTarget> targets = new TargetRepository(settings.targetsRoot()).load(settings.selection());
        assertThat(targets).as("targets selected by %s", settings.selection()).isNotEmpty();
        return settings.allChecks()
                ? scheduled.forSharedArms(SharedTargetArms.of(targets), new SharedArmPlanner(harness, this)::plan)
                : scheduled.forTargets(targets, this::planned);
    }

    private Optional<Supplier<ArmResult>> planned(LoadedTarget target, TargetArm arm) {
        AuthStrategy auth = target.manifest().auth().including(arm.headers()).strategy();
        ArmIdentities identities = identities(target, arm, auth);
        McpEventLog checkLog = checkLog();
        AuditedArm audited = harness.newArm(target.manifest());
        Optional<McpCheck> check = target.manifest().checkAccess()
                ? Optional.of(new CheckAccessSubject(target.manifest().check()))
                : catalog(checkLog, auth, identities, audited).find(target.manifest().check());
        if (check.isEmpty()) {
            checkLog.shutdown();
        }
        return check.map(found -> () -> runLogged(
                ArmRun.asDeclared(target, arm, found, auth, identities, checkLog), audited));
    }

    private ArmResult runLogged(ArmRun run, AuditedArm audited) {
        try {
            return harness.run(run, audited);
        } finally {
            audited.lateIssues().close();
            run.checkLog().shutdown();
        }
    }

    @Override
    public ArmIdentities identities(LoadedTarget target, TargetArm arm, AuthStrategy auth) {
        return new ArmIdentities(target, arm.name(), auth, identityScripts);
    }

    @Override
    public McpEventLog checkLog() {
        return new McpEventLog(mock(Logging.class));
    }

    @Override
    public CheckCatalog catalog(McpEventLog checkLog, AuthStrategy auth, ArmIdentities identities,
                                AuditedArm audited) {
        return CheckCatalog.discover(audited.lateIssues().collectingFor(new CheckServices(checkLog, () -> auth,
                collaborator.forOneArm(), audited.probeService(), identities, identities.ledger(), identities,
                audited.probeService().sseProbeStreams()).withSignedInConsent(identities.signedInConsent())));
    }
}
