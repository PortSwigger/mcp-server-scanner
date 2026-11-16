package com.mcpscanner.ui;

import com.mcpscanner.testutil.ManualReadScheduler;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class PlannedRequestCountsTest {

    private final ManualReadScheduler scheduler = new ManualReadScheduler();
    private final PlannedRequestCounts<Integer> counts = new PlannedRequestCounts<>(scheduler.reads());
    private final AtomicInteger plans = new AtomicInteger();
    private final AtomicInteger counted = new AtomicInteger();

    PlannedRequestCountsTest() {
        counts.onCounted(counted::incrementAndGet);
    }

    @Test
    void anUnknownCountIsPlannedInTheBackgroundAndReportedWhenItArrives() {
        assertThat(counts.count("a", this::plan)).isEmpty();
        assertThat(plans).hasValue(0);

        scheduler.runNext();

        assertThat(counted).hasValue(1);
        assertThat(counts.count("a", this::plan)).contains(1);
        assertThat(plans).hasValue(1);
        assertThat(scheduler.pendingCount()).isZero();
    }

    @Test
    void aKeyAlreadyBeingCountedIsNotPlannedTwice() {
        counts.count("a", this::plan);
        counts.count("a", this::plan);

        assertThat(scheduler.pendingCount()).isEqualTo(1);
    }

    @Test
    void differentKeysAreCountedSeparately() {
        counts.count("a", () -> 3);
        counts.count("b", () -> 7);
        scheduler.runAll();

        assertThat(counts.count("a", this::plan)).contains(3);
        assertThat(counts.count("b", this::plan)).contains(7);
    }

    @Test
    void aCountPlannedBeforeInvalidationIsDropped() {
        counts.count("a", () -> 3);
        counts.invalidate();

        scheduler.runNext();

        assertThat(counted).hasValue(0);
        assertThat(counts.count("a", () -> 9)).isEmpty();
        scheduler.runNext();
        assertThat(counts.count("a", this::plan)).contains(9);
    }

    @Test
    void invalidationForgetsKnownCounts() {
        counts.count("a", () -> 3);
        scheduler.runNext();

        counts.invalidate();

        assertThat(counts.count("a", () -> 4)).isEmpty();
        assertThat(scheduler.pendingCount()).isEqualTo(1);
    }

    @Test
    void anImmediateCountIsReturnedToTheCallerThatStartedIt() {
        PlannedRequestCounts<Integer> immediate = new PlannedRequestCounts<>(ManualReadScheduler.immediateReads());

        assertThat(immediate.count("a", () -> 5)).contains(5);
    }

    @Test
    void onlyTheMostRecentlyUsedCountsAreKept() {
        for (int key = 0; key < PlannedRequestCounts.CAPACITY + 1; key++) {
            counts.count(key, () -> 1);
        }
        scheduler.runAll();

        assertThat(counts.count(0, this::plan)).isEmpty();
        assertThat(counts.count(PlannedRequestCounts.CAPACITY, this::plan)).contains(1);
    }

    private int plan() {
        return plans.incrementAndGet();
    }
}
