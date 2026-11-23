package com.mcpscanner.cvetargets.environment;

import com.mcpscanner.cvetargets.run.ArmSchedule;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class HelperNameLeasesTest {

    private static final Duration PATIENCE = Duration.ofSeconds(5);

    private final List<String> log = new CopyOnWriteArrayList<>();
    private final HelperNameLeases leases = new HelperNameLeases(log::add);

    @Test
    void aSecondArmNeedingAHeldHelperNameWaitsUntilTheFirstReleasesIt() {
        HelperNameLeases.Lease first = leases.acquire("target/vulnerable", Set.of("target-db"));

        CompletableFuture<HelperNameLeases.Lease> second =
                CompletableFuture.supplyAsync(() -> leases.acquire("target/fixed", Set.of("target-db")));
        await().atMost(PATIENCE).until(() -> !log.isEmpty());
        assertThat(second).isNotDone();

        first.close();

        await().atMost(PATIENCE).until(second::isDone);
        second.join().close();
    }

    @Test
    void saysWhichNamesItIsWaitingFor() {
        HelperNameLeases.Lease first = leases.acquire("target/vulnerable", Set.of("target-db"));

        CompletableFuture<HelperNameLeases.Lease> second = CompletableFuture.supplyAsync(
                () -> leases.acquire("target/fixed", Set.of("target-db", "target-cache")));
        await().atMost(PATIENCE).until(() -> !log.isEmpty());
        first.close();
        second.join().close();

        assertThat(log).singleElement().asString()
                .contains("target/fixed").contains("[target-db]").contains("another arm");
    }

    @Test
    void armsWithDisjointHelperNamesRunTogether() {
        try (HelperNameLeases.Lease first = leases.acquire("a/vulnerable", Set.of("a-db"));
             HelperNameLeases.Lease second = leases.acquire("b/vulnerable", Set.of("b-db"))) {
            assertThat(log).isEmpty();
        }
    }

    @Test
    void armsWithoutHelpersNeverWait() {
        try (HelperNameLeases.Lease first = leases.acquire("a/vulnerable", Set.of());
             HelperNameLeases.Lease second = leases.acquire("a/fixed", Set.of())) {
            assertThat(log).isEmpty();
        }
    }

    @Test
    void closingALeaseTwiceReleasesOnlyItsOwnNames() {
        HelperNameLeases.Lease first = leases.acquire("target/vulnerable", Set.of("target-db"));
        first.close();
        HelperNameLeases.Lease second = leases.acquire("target/fixed", Set.of("target-db"));

        first.close();

        CompletableFuture<HelperNameLeases.Lease> third =
                CompletableFuture.supplyAsync(() -> leases.acquire("target/other", Set.of("target-db")));
        await().atMost(PATIENCE).until(() -> !log.isEmpty());
        assertThat(third).isNotDone();
        second.close();
        third.join().close();
    }

    @Test
    void anArmWaitingForAHelperNameGivesItsRunSlotToTheNextArmsMeanwhile() {
        CountDownLatch holderLeased = new CountDownLatch(1);
        CountDownLatch otherArmsFinished = new CountDownLatch(2);
        try (ArmSchedule schedule = new ArmSchedule(2)) {
            CompletableFuture<Boolean> holder = schedule.submit(() -> {
                try (HelperNameLeases.Lease lease = leases.acquire("shared/fixed", Set.of("shared-api"))) {
                    holderLeased.countDown();
                    return awaited(otherArmsFinished);
                }
            });
            assertThat(awaited(holderLeased)).isTrue();
            CompletableFuture<Boolean> waiter = schedule.submit(() -> {
                leases.acquire("shared/vulnerable", Set.of("shared-api")).close();
                return true;
            });
            List<CompletableFuture<Boolean>> others = List.of(
                    schedule.submit(() -> finished(otherArmsFinished)),
                    schedule.submit(() -> finished(otherArmsFinished)));

            await().atMost(PATIENCE).until(() -> holder.isDone() && waiter.isDone());
            assertThat(holder).isCompletedWithValue(true);
            assertThat(others).allSatisfy(other -> assertThat(other).isCompletedWithValue(true));
        }
    }

    private static boolean finished(CountDownLatch armsFinished) {
        armsFinished.countDown();
        return true;
    }

    private static boolean awaited(CountDownLatch latch) {
        try {
            return latch.await(PATIENCE.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
