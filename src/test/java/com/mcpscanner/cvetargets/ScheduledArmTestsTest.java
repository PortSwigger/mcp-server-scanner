package com.mcpscanner.cvetargets;

import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.ManifestFixtures;
import com.mcpscanner.cvetargets.manifest.TargetRepository;
import com.mcpscanner.cvetargets.manifest.TargetSelection;
import com.mcpscanner.cvetargets.manifest.ArmRole;
import com.mcpscanner.cvetargets.manifest.ExpectedOutcome;
import com.mcpscanner.cvetargets.manifest.Outcome;
import com.mcpscanner.cvetargets.run.ArmDurations;
import com.mcpscanner.cvetargets.run.ArmKey;
import com.mcpscanner.cvetargets.run.ArmResult;
import com.mcpscanner.cvetargets.run.ProbeTally;
import com.mcpscanner.cvetargets.run.ArmSchedule;
import com.mcpscanner.cvetargets.shared.SharedTargetArm;
import com.mcpscanner.cvetargets.shared.SharedTargetArms;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opentest4j.TestAbortedException;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScheduledArmTestsTest {

    @TempDir
    Path root;

    @Test
    void submitsEveryArmBeforeAnyTestWaitsSoArmsOverlapUpToTheParallelism() {
        CountDownLatch allArmsRunning = new CountDownLatch(2);
        try (ArmSchedule schedule = new ArmSchedule(2)) {
            List<DynamicNode> tests = new ScheduledArmTests(schedule, durations()).forTargets(List.of(target()),
                    (target, arm) -> Optional.of(() -> {
                        allArmsRunning.countDown();
                        awaitQuietly(allArmsRunning);
                        return passed();
                    }));

            assertTimeoutPreemptively(Duration.ofSeconds(10), armTests(tests).get(0).getExecutable());
        }
    }

    @Test
    void anArmWithoutAPlanIsSkippedAndAFailedArmFailsItsTest() {
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            List<DynamicTest> arms = armTests(new ScheduledArmTests(schedule, durations()).forTargets(List.of(target()),
                    (target, arm) -> arm.name().equals("vulnerable") ? Optional.empty() : Optional.of(this::failed)));

            assertThrows(TestAbortedException.class, arms.get(0).getExecutable());
            assertThat(assertThrows(AssertionError.class, arms.get(1).getExecutable()))
                    .hasMessageContaining("expected FIRE");
        }
    }

    @Test
    void runsEachSharedArmOnceAndGivesEveryManifestArmItsOwnTest() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        ManifestFixtures.writeValidTarget(root, "check-b", "target-two");
        List<SharedTargetArm> shared = SharedTargetArms.of(new TargetRepository(root).load(TargetSelection.everything()));
        AtomicInteger plans = new AtomicInteger();
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            ScheduledArmTests scheduled = new ScheduledArmTests(schedule, durations());
            List<DynamicNode> tests = scheduled.forSharedArms(shared, arm -> () -> {
                plans.incrementAndGet();
                return arm.members().stream().map(member -> result(member.target().manifest().check(),
                        member.target().manifest().id(), member.arm().name())).toList();
            });

            assertThat(tests).extracting(DynamicNode::getDisplayName)
                    .containsExactly("check-a/target-one", "check-b/target-two");
            List<DynamicTest> arms = armTests(tests);
            assertThat(arms).extracting(DynamicNode::getDisplayName)
                    .containsExactly("vulnerable", "fixed", "vulnerable", "fixed");
            assertThrows(TestAbortedException.class, arms.get(0).getExecutable());
            assertThat(assertThrows(AssertionError.class, arms.get(1).getExecutable())).hasMessageContaining("fixed by check-a");
            assertThrows(TestAbortedException.class, arms.get(2).getExecutable());
            assertThrows(AssertionError.class, arms.get(3).getExecutable());
            assertThat(plans).hasValue(2);
            assertThat(scheduled.completedResults()).hasSize(4);
        }
    }

    @Test
    void reportsAnArmWhoseRunThrewAndAnArmWithoutAPlanSoNoArmIsMissingFromTheSummary() {
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            ScheduledArmTests scheduled = new ScheduledArmTests(schedule, durations());
            List<DynamicTest> arms = armTests(scheduled.forTargets(List.of(target()),
                    (target, arm) -> arm.name().equals("vulnerable") ? Optional.empty() : Optional.of(() -> {
                        throw new IllegalStateException("harness crashed");
                    })));
            arms.forEach(arm -> assertThrows(Throwable.class, arm.getExecutable()));

            assertThat(scheduled.completedResults())
                    .extracting(ArmResult::check, ArmResult::target, ArmResult::arm, ArmResult::passed)
                    .containsExactlyInAnyOrder(tuple("check-a", "target-one", "vulnerable", false),
                            tuple("check-a", "target-one", "fixed", false));
            assertThat(scheduled.completedResults()).filteredOn(result -> result.arm().equals("vulnerable"))
                    .singleElement().satisfies(result ->
                            assertThat(result.notRunnable()).isEqualTo("check check-a is not in the catalog yet"));
            assertThat(scheduled.completedResults()).filteredOn(result -> result.arm().equals("fixed"))
                    .singleElement().satisfies(result -> assertThat(result.error()).contains("harness crashed"));
        }
    }

    @Test
    void submitsTheLongestRecordedArmFirstButKeepsTheTestsInDeclaredOrder() {
        LoadedTarget target = target();
        new ArmDurations(durationsFile(), message -> { }).record(ran(target, "fixed", 900_000));
        new ArmDurations(durationsFile(), message -> { }).record(ran(target, "vulnerable", 60_000));
        List<String> started = new CopyOnWriteArrayList<>();
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            List<DynamicTest> arms = armTests(new ScheduledArmTests(schedule, durations()).forTargets(List.of(target),
                    (loaded, arm) -> Optional.of(() -> {
                        started.add(arm.name());
                        return passed();
                    })));

            assertThat(arms).extracting(DynamicNode::getDisplayName).containsExactly("vulnerable", "fixed");
            arms.forEach(arm -> assertDoesNotThrow(arm.getExecutable()));
            assertThat(started).containsExactly("fixed", "vulnerable");
        }
    }

    @Test
    void recordsHowLongEachArmRanOnceItCompletes() {
        LoadedTarget target = target();
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            List<DynamicTest> arms = armTests(new ScheduledArmTests(schedule, durations()).forTargets(List.of(target),
                    (loaded, arm) -> Optional.of(() -> ran(loaded, arm.name(), 42_000))));
            arms.forEach(arm -> assertDoesNotThrow(arm.getExecutable()));
        }

        assertThat(durations().recorded(new ArmKey("check-a", "target-one", "fixed"))).hasValue(42_000);
    }

    private ArmDurations durations() {
        return new ArmDurations(durationsFile(), message -> { });
    }

    private Path durationsFile() {
        return root.resolve("history").resolve("durations.json");
    }

    private static ArmResult ran(LoadedTarget target, String arm, long durationMillis) {
        return new ArmResult(target.manifest().check(), target.manifest().id(), arm, "direct", ArmRole.FIXED, "1.0.0",
                ExpectedOutcome.of(Outcome.SILENT), Outcome.SILENT, true, "ok", List.of(), 1, 0, ProbeTally.NONE,
                durationMillis, "2026-11-19T00:00:00Z", null, null, null, null, Map.of(), null);
    }

    private static ArmResult result(String check, String target, String arm) {
        ArmResult result = mock(ArmResult.class);
        when(result.check()).thenReturn(check);
        when(result.target()).thenReturn(target);
        when(result.arm()).thenReturn(arm);
        when(result.verdict()).thenReturn(arm + " by " + check);
        when(result.notRunnable()).thenReturn(arm.equals("vulnerable") ? "not runnable here" : null);
        return result;
    }

    private LoadedTarget target() {
        ManifestFixtures.writeValidTarget(root, "check-a", "target-one");
        return ManifestFixtures.loadOnly(root, "check-a", "target-one");
    }

    private static List<DynamicTest> armTests(List<DynamicNode> tests) {
        return tests.stream().map(DynamicContainer.class::cast).flatMap(DynamicContainer::getChildren)
                .map(DynamicTest.class::cast).toList();
    }

    private static ArmResult passed() {
        ArmResult result = mock(ArmResult.class);
        when(result.passed()).thenReturn(true);
        return result;
    }

    private ArmResult failed() {
        ArmResult result = mock(ArmResult.class);
        when(result.verdict()).thenReturn("expected FIRE, observed 0 matching of 0 issues");
        return result;
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
