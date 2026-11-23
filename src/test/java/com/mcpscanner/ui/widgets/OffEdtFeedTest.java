package com.mcpscanner.ui.widgets;

import com.mcpscanner.testutil.ManualReadScheduler;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class OffEdtFeedTest {

    private static final long INTERVAL = 250;

    private final ManualReadScheduler scheduler = new ManualReadScheduler();
    private final AtomicInteger reads = new AtomicInteger();
    private final List<Integer> applied = new ArrayList<>();
    private final OffEdtFeed<Integer> feed = scheduler.reads().feed(INTERVAL, reads::incrementAndGet, applied::add);

    @Test
    void readsTheSourceOnTheSchedulerAndAppliesTheValue() {
        feed.request();

        assertThat(reads).hasValue(0);
        scheduler.runNext();

        assertThat(applied).containsExactly(1);
    }

    @Test
    void requestsWhileAReadIsPendingShareThatRead() {
        feed.request();
        feed.request();
        feed.request();

        assertThat(scheduler.pendingCount()).isEqualTo(1);
        scheduler.runNext();
        assertThat(reads).hasValue(1);
    }

    @Test
    void theFirstReadIsImmediate() {
        feed.request();

        assertThat(scheduler.lastDelay()).isZero();
    }

    @Test
    void aReadSoonAfterTheLastWaitsOutTheInterval() {
        feed.request();
        scheduler.runNext();
        scheduler.advance(100);

        feed.request();

        assertThat(scheduler.lastDelay()).isEqualTo(INTERVAL - 100);
    }

    @Test
    void aReadLongAfterTheLastIsImmediate() {
        feed.request();
        scheduler.runNext();
        scheduler.advance(INTERVAL * 4);

        feed.request();

        assertThat(scheduler.lastDelay()).isZero();
    }

    @Test
    void aChangeDuringAReadIsReadAgain() {
        AtomicReference<OffEdtFeed<Integer>> changing = new AtomicReference<>();
        changing.set(scheduler.reads().feed(INTERVAL, () -> {
            int read = reads.incrementAndGet();
            if (read == 1) {
                changing.get().request();
            }
            return read;
        }, applied::add));

        changing.get().request();
        scheduler.runNext();
        scheduler.runNext();

        assertThat(applied).containsExactly(1, 2);
    }

    @Test
    void runsWorkOnTheSchedulerNotTheCaller() {
        AtomicInteger ran = new AtomicInteger();

        scheduler.reads().run(ran::incrementAndGet);

        assertThat(ran).hasValue(0);
        scheduler.runNext();
        assertThat(ran).hasValue(1);
    }

    @Test
    void aCancelledFeedNeitherReadsNorApplies() {
        feed.request();
        feed.cancel();
        scheduler.runAll();
        feed.request();
        feed.requestLater(1000);

        assertThat(reads).hasValue(0);
        assertThat(applied).isEmpty();
        assertThat(scheduler.pendingCount()).isZero();
    }

    @Test
    void aValueReadBeforeCancelIsNotApplied() {
        List<Runnable> edt = new ArrayList<>();
        OffEdtFeed<Integer> deferred = new UiReads(scheduler, edt::add, (message, failure) -> { })
                .feed(INTERVAL, reads::incrementAndGet, applied::add);
        deferred.request();
        scheduler.runNext();

        deferred.cancel();
        edt.forEach(Runnable::run);

        assertThat(applied).isEmpty();
    }

    @Test
    void aLaterRequestReadsAfterTheDelayWithoutHoldingUpPromptRequests() {
        feed.request();
        feed.requestLater(1000);

        assertThat(scheduler.lastDelay()).isEqualTo(1000);
        assertThat(scheduler.pendingCount()).isEqualTo(2);
        scheduler.runAll();
        assertThat(reads).hasValue(2);
    }

    @Test
    void laterRequestsWhileOneIsWaitingShareIt() {
        feed.requestLater(1000);
        feed.requestLater(1000);

        assertThat(scheduler.pendingCount()).isEqualTo(1);
    }

    @Test
    void aFailingReadIsLoggedAtDebugAndTheFeedCarriesOn() {
        AtomicInteger attempts = new AtomicInteger();
        OffEdtFeed<Integer> failing = scheduler.reads().feed(0, () -> {
            if (attempts.incrementAndGet() == 1) {
                throw new IllegalStateException("boom");
            }
            return attempts.get();
        }, applied::add);

        failing.request();
        scheduler.runNext();
        failing.request();
        scheduler.runNext();

        assertThat(scheduler.failures).singleElement().isInstanceOf(IllegalStateException.class);
        assertThat(applied).containsExactly(2);
    }

    @Test
    void workThatFailsIsLoggedAtDebug() {
        scheduler.reads().run(() -> {
            throw new IllegalArgumentException("bad");
        });
        scheduler.runNext();

        assertThat(scheduler.failures).singleElement().isInstanceOf(IllegalArgumentException.class);
    }
}
