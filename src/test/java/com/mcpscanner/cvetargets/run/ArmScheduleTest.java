package com.mcpscanner.cvetargets.run;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

class ArmScheduleTest {

    @Test
    void runsUpToItsParallelismOfArmsAtOnce() {
        CountDownLatch bothRunning = new CountDownLatch(2);
        try (ArmSchedule schedule = new ArmSchedule(2)) {
            CompletableFuture<String> first = schedule.submit(() -> awaitPeer(bothRunning, "first"));
            CompletableFuture<String> second = schedule.submit(() -> awaitPeer(bothRunning, "second"));

            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(20))
                    .until(() -> first.isDone() && second.isDone());
            assertThat(first).isCompletedWithValue("first");
            assertThat(second).isCompletedWithValue("second");
        }
    }

    @Test
    void runsArmsOneAfterAnotherInSubmissionOrderWithAParallelismOfOne() {
        List<String> order = new CopyOnWriteArrayList<>();
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            List<CompletableFuture<Boolean>> arms = List.of("a", "b", "c").stream()
                    .map(name -> schedule.submit(() -> order.add(name)))
                    .toList();
            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(20))
                    .until(() -> arms.stream().allMatch(CompletableFuture::isDone));
            assertThat(arms).allSatisfy(arm -> assertThat(arm).isCompletedWithValue(true));
        }

        assertThat(order).containsExactly("a", "b", "c");
    }

    @Test
    void rejectsAParallelismBelowOne() {
        assertThatThrownBy(() -> new ArmSchedule(0)).isInstanceOf(IllegalArgumentException.class);
    }

    private static String awaitPeer(CountDownLatch bothRunning, String name) {
        bothRunning.countDown();
        try {
            assertThat(bothRunning.await(10, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        return name;
    }

    @Test
    void anArmWaitingOutsideItsSlotLetsTheNextQueuedArmRun() {
        CountDownLatch nextArmRan = new CountDownLatch(1);
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            CompletableFuture<Boolean> waiting = schedule.submit(() -> {
                ArmSchedule.waitOutsideItsSlot(() -> awaitQuietly(nextArmRan));
                return true;
            });
            CompletableFuture<Boolean> next = schedule.submit(() -> {
                nextArmRan.countDown();
                return true;
            });

            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(20))
                    .until(() -> waiting.isDone() && next.isDone());
            assertThat(waiting).isCompletedWithValue(true);
        }
    }

    @Test
    void anArmWhoseWaitEndedTakesTheNextFreeSlotBeforeQueuedArmsAndNeverExceedsTheParallelism() {
        List<String> order = new CopyOnWriteArrayList<>();
        CountDownLatch waitEnds = new CountDownLatch(1);
        CountDownLatch runningArmMayFinish = new CountDownLatch(1);
        AtomicInteger inSlot = new AtomicInteger();
        AtomicInteger mostInSlot = new AtomicInteger();
        try (ArmSchedule schedule = new ArmSchedule(1)) {
            CompletableFuture<Boolean> waiting = schedule.submit(() -> {
                ArmSchedule.waitOutsideItsSlot(() -> awaitQuietly(waitEnds));
                return counted(inSlot, mostInSlot, () -> order.add("resumed"));
            });
            CompletableFuture<Boolean> running = schedule.submit(() -> counted(inSlot, mostInSlot, () -> {
                waitEnds.countDown();
                awaitQuietly(runningArmMayFinish);
                return order.add("ran");
            }));
            CompletableFuture<Boolean> queued = schedule.submit(() -> counted(inSlot, mostInSlot,
                    () -> order.add("queued")));
            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(20))
                    .until(schedule::hasAnArmResuming);

            runningArmMayFinish.countDown();

            await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(20))
                    .until(() -> waiting.isDone() && running.isDone() && queued.isDone());
        }

        assertThat(order).containsExactly("ran", "resumed", "queued");
        assertThat(mostInSlot).hasValue(1);
    }

    @Test
    void refusesArmsOnceClosed() {
        ArmSchedule schedule = new ArmSchedule(1);
        schedule.close();

        assertThatThrownBy(() -> schedule.submit(() -> true)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void waitingOutsideASlotOffTheScheduleJustWaits() {
        AtomicInteger waited = new AtomicInteger();

        ArmSchedule.waitOutsideItsSlot(waited::incrementAndGet);

        assertThat(waited).hasValue(1);
    }

    private static <T> T counted(AtomicInteger inSlot, AtomicInteger mostInSlot, Supplier<T> work) {
        mostInSlot.accumulateAndGet(inSlot.incrementAndGet(), Math::max);
        try {
            return work.get();
        } finally {
            inSlot.decrementAndGet();
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            assertThat(latch.await(10, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
