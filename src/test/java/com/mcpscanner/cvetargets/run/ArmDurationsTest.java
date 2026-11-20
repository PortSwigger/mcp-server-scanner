package com.mcpscanner.cvetargets.run;

import com.mcpscanner.cvetargets.manifest.ArmRole;
import com.mcpscanner.cvetargets.manifest.ExpectedOutcome;
import com.mcpscanner.cvetargets.manifest.Outcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ArmDurationsTest {

    private static final ArmKey FIXED = new ArmKey("check-a", "target-one", "fixed");
    private static final ArmKey VULNERABLE = new ArmKey("check-a", "target-one", "vulnerable");

    @TempDir
    Path root;

    private final List<String> log = new ArrayList<>();

    @Test
    void remembersHowLongAnArmRanWithoutItsSlotWaitForTheNextRun() {
        Path file = root.resolve("history/cveTargetsBurp/extensions-only.json");
        new ArmDurations(file, log::add).record(ran("fixed", 900_000, 300_000));

        ArmDurations nextRun = new ArmDurations(file, log::add);

        assertThat(nextRun.recorded(FIXED)).hasValue(600_000);
        assertThat(nextRun.recorded(VULNERABLE)).isEmpty();
        assertThat(log).isEmpty();
    }

    @Test
    void keepsWhatAnotherRunRecordedAfterThisOneLoadedAndLeavesNoTemporaryFiles() throws IOException {
        Path file = root.resolve("durations.json");
        ArmDurations first = new ArmDurations(file, log::add);
        new ArmDurations(file, log::add).record(ran("vulnerable", 5_000, 0));

        first.record(ran("fixed", 7_000, 1_000));

        ArmDurations merged = new ArmDurations(file, log::add);
        assertThat(merged.recorded(VULNERABLE)).hasValue(5_000);
        assertThat(merged.recorded(FIXED)).hasValue(6_000);
        try (var files = Files.list(root)) {
            assertThat(files).containsExactly(file);
        }
    }

    @Test
    void doesNotRecordAnArmThatCouldNotRunOrCrashedBeforeRunning() {
        Path file = root.resolve("durations.json");
        ArmDurations durations = new ArmDurations(file, log::add);
        durations.record(new ArmResult("check-a", "target-one", "vulnerable", null, ArmRole.VULNERABLE, "1.0.0",
                ExpectedOutcome.of(Outcome.FIRE), null, false, "not runnable: no OAuth", List.of(), 0, 0,
                ProbeTally.NONE, 4_000, null, null, null, null, null, null, null, Map.of(), "no OAuth"));
        durations.record(new ArmResult("check-a", "target-one", "fixed", null, ArmRole.FIXED, "1.0.1",
                ExpectedOutcome.of(Outcome.SILENT), null, false, "run failed", List.of(), 0, 0, ProbeTally.NONE, 0,
                null, "IllegalStateException: boom", null, null, null, null, null, Map.of(), null));

        ArmDurations nextRun = new ArmDurations(file, log::add);
        assertThat(nextRun.recorded(VULNERABLE)).isEmpty();
        assertThat(nextRun.recorded(FIXED)).isEmpty();
    }

    @Test
    void keepsTheLastGoodDurationWhenAnArmFailsPartWay() {
        Path file = root.resolve("durations.json");
        ArmDurations durations = new ArmDurations(file, log::add);
        durations.record(ran("fixed", 900_000, 0));
        durations.record(new ArmResult("check-a", "target-one", "fixed", "burp", ArmRole.FIXED, "1.0.1",
                ExpectedOutcome.of(Outcome.SILENT), null, false, "run failed: port clash", List.of(), 0, 0,
                ProbeTally.NONE, 4_000, "2026-11-19T00:00:00Z", "IllegalStateException: port clash", null, null,
                null, Map.of(ArmPhase.SLOT_WAIT.jsonName(), 0L), null));

        assertThat(new ArmDurations(file, log::add).recorded(FIXED)).hasValue(900_000);
    }

    @Test
    void treatsAnUnreadableHistoryAsEmptySayingSoOnceAndThenReplacesIt() throws IOException {
        Path file = root.resolve("durations.json");
        Files.writeString(file, "{ not json");

        ArmDurations durations = new ArmDurations(file, log::add);
        durations.record(ran("fixed", 2_000, 0));

        assertThat(log).singleElement().asString().contains(file.toString());
        assertThat(new ArmDurations(file, log::add).recorded(FIXED)).hasValue(2_000);
    }

    private static ArmResult ran(String arm, long durationMillis, long slotWaitMillis) {
        return new ArmResult("check-a", "target-one", arm, "direct", ArmRole.FIXED, "1.0.1",
                ExpectedOutcome.of(Outcome.SILENT), Outcome.SILENT, true, "ok", List.of(), 1, 0, ProbeTally.NONE,
                durationMillis, "2026-11-19T00:00:00Z", null, null, null, null,
                Map.of(ArmPhase.SLOT_WAIT.jsonName(), slotWaitMillis), null);
    }
}
