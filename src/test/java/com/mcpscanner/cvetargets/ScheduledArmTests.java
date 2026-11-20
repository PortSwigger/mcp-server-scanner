package com.mcpscanner.cvetargets;

import com.mcpscanner.cvetargets.environment.MachineSlots;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.TargetArm;
import com.mcpscanner.cvetargets.run.ArmDurations;
import com.mcpscanner.cvetargets.run.ArmEstimate;
import com.mcpscanner.cvetargets.run.ArmKey;
import com.mcpscanner.cvetargets.run.ArmOrder;
import com.mcpscanner.cvetargets.run.ArmResult;
import com.mcpscanner.cvetargets.run.ArmSchedule;
import com.mcpscanner.cvetargets.shared.ManifestArm;
import com.mcpscanner.cvetargets.shared.SharedTargetArm;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

final class ScheduledArmTests {

    private final ArmSchedule schedule;
    private final ArmDurations durations;
    private final List<TrackedArm> submitted = new CopyOnWriteArrayList<>();

    ScheduledArmTests(ArmSchedule schedule, ArmDurations durations) {
        this.schedule = schedule;
        this.durations = durations;
    }

    List<DynamicNode> forTargets(List<LoadedTarget> targets,
                                 BiFunction<LoadedTarget, TargetArm, Optional<Supplier<ArmResult>>> plannedArms) {
        List<ManifestArm> declared = targets.stream()
                .flatMap(target -> target.manifest().arms().stream().map(arm -> new ManifestArm(target, arm)))
                .toList();
        Map<ManifestArm, CompletableFuture<ArmResult>> results = new LinkedHashMap<>();
        ArmOrder.longestFirst(declared, this::estimate).forEach(member ->
                results.put(member, submitted(member.target(), member.arm(), plannedArms)));
        return byTarget(declared, results);
    }

    List<DynamicNode> forSharedArms(List<SharedTargetArm> sharedArms,
                                    Function<SharedTargetArm, Supplier<List<ArmResult>>> plannedArms) {
        Map<ManifestArm, CompletableFuture<ArmResult>> results = new LinkedHashMap<>();
        ArmOrder.longestFirst(sharedArms, this::estimate).forEach(shared -> {
            CompletableFuture<List<ArmResult>> pending = schedule.submit(plannedArms.apply(shared));
            shared.members().forEach(member -> results.put(member,
                    tracked(member.target(), member.arm(), pending.thenApply(all -> resultOf(member, all)))));
        });
        return byTarget(sharedArms.stream().flatMap(shared -> shared.members().stream()).toList(), results);
    }

    List<ArmResult> completedResults() {
        return submitted.stream().map(TrackedArm::result).toList();
    }

    private ArmEstimate estimate(SharedTargetArm shared) {
        return ArmEstimate.together(shared.members().stream().map(this::estimate).toList());
    }

    private ArmEstimate estimate(ManifestArm member) {
        int slots = MachineSlots.slotsFor(member.target().manifest().footprintMb());
        OptionalLong ranMillis = durations.recorded(new ArmKey(member.target().manifest().check(),
                member.target().manifest().id(), member.arm().name()));
        return new ArmEstimate(ranMillis, slots, member.target().manifest().startFirst());
    }

    private static List<DynamicNode> byTarget(List<ManifestArm> declared,
                                              Map<ManifestArm, CompletableFuture<ArmResult>> results) {
        Map<LoadedTarget, List<DynamicNode>> byTarget = new LinkedHashMap<>();
        declared.forEach(member -> byTarget.computeIfAbsent(member.target(), target -> new ArrayList<>())
                .add(DynamicTest.dynamicTest(member.arm().name(),
                        judged(member.target(), member.arm(), results.get(member)))));
        return byTarget.entrySet().stream().<DynamicNode>map(entry ->
                DynamicContainer.dynamicContainer(entry.getKey().displayName(), entry.getValue())).toList();
    }

    private CompletableFuture<ArmResult> submitted(LoadedTarget target, TargetArm arm,
                                                   BiFunction<LoadedTarget, TargetArm, Optional<Supplier<ArmResult>>> plannedArms) {
        String check = target.manifest().check();
        CompletableFuture<ArmResult> pending = plannedArms.apply(target, arm).map(schedule::submit)
                .orElseGet(() -> CompletableFuture.completedFuture(ArmResult.notRunnable(check, target, arm, null,
                        "check " + check + " is not in the catalog yet")));
        return tracked(target, arm, pending);
    }

    private CompletableFuture<ArmResult> tracked(LoadedTarget target, TargetArm arm,
                                                 CompletableFuture<ArmResult> pending) {
        submitted.add(new TrackedArm(target, arm, pending));
        return pending.thenApply(this::recorded);
    }

    private ArmResult recorded(ArmResult result) {
        durations.record(result);
        return result;
    }

    private static ArmResult resultOf(ManifestArm member, List<ArmResult> results) {
        return results.stream()
                .filter(result -> result.check().equals(member.target().manifest().check())
                        && result.target().equals(member.target().manifest().id())
                        && result.arm().equals(member.arm().name()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("no result for " + member.target().displayName() + "/"
                        + member.arm().name()));
    }

    private record TrackedArm(LoadedTarget target, TargetArm arm, CompletableFuture<ArmResult> pending) {

        ArmResult result() {
            try {
                return pending.join();
            } catch (CompletionException | CancellationException failed) {
                return ArmResult.crashed(target.manifest().check(), target, arm,
                        failed.getCause() == null ? failed : failed.getCause());
            }
        }
    }

    private static Executable judged(LoadedTarget target, TargetArm arm, CompletableFuture<ArmResult> pending) {
        return () -> {
            ArmResult result = pending.join();
            assumeTrue(result.notRunnable() == null, () -> "not runnable: " + result.notRunnable());
            assertThat(result.passed()).as("%s/%s: %s", target.displayName(), arm.name(), result.verdict()).isTrue();
        };
    }
}
