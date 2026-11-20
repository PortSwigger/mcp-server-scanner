package com.mcpscanner.access.comparison;

import com.mcpscanner.access.AccessRunStopped;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.TestPrincipals;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PrincipalFanOutTest {

    private static final Principal B = TestPrincipals.peer("B");
    private static final Principal C = TestPrincipals.peer("C");
    private static final Principal D = TestPrincipals.peer("D");

    private final ExecutorService pool = Executors.newFixedThreadPool(3);

    @AfterEach
    void stopPool() {
        pool.shutdownNow();
    }

    @Test
    void aPoolRunsEveryIdentitysWorkAtTheSameTime() {
        CountDownLatch allStarted = new CountDownLatch(3);

        List<Boolean> metTheOthers = List.copyOf(new PrincipalFanOut(pool).each(List.of(B, C, D), principal -> {
            allStarted.countDown();
            return awaited(allStarted);
        }).values());

        assertThat(metTheOthers).containsExactly(true, true, true);
    }

    @Test
    void resultsKeepTheIdentitiesOrderWhateverOrderTheyFinishIn() {
        CountDownLatch bMayFinish = new CountDownLatch(1);

        var results = new PrincipalFanOut(pool).each(List.of(B, C), principal -> {
            if (principal == B) {
                awaited(bMayFinish);
            } else {
                bMayFinish.countDown();
            }
            return principal.name();
        });

        assertThat(results.keySet()).containsExactly(B, C);
        assertThat(results.values()).containsExactly("identity-B", "identity-C");
    }

    @Test
    void inTurnStopsAtTheFirstFailureAndRethrowsIt() {
        List<Principal> started = new ArrayList<>();

        assertThatThrownBy(() -> PrincipalFanOut.inTurn().each(List.of(B, C, D), principal -> {
            started.add(principal);
            if (principal == C) {
                throw new AccessRunStopped("the server answered HTTP 429 Too Many Requests");
            }
            return principal;
        })).isInstanceOf(AccessRunStopped.class);

        assertThat(started).containsExactly(B, C);
    }

    @Test
    void aPoolWaitsForEveryIdentityBeforeRethrowingAFailure() {
        List<Principal> finished = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch cStarted = new CountDownLatch(1);
        CountDownLatch bFailing = new CountDownLatch(1);

        assertThatThrownBy(() -> new PrincipalFanOut(pool).each(List.of(B, C), principal -> {
            if (principal == B) {
                awaited(cStarted);
                bFailing.countDown();
                throw new AccessRunStopped("stopped");
            }
            cStarted.countDown();
            awaited(bFailing);
            finished.add(principal);
            return principal;
        })).isInstanceOf(AccessRunStopped.class);

        assertThat(finished).containsExactly(C);
    }

    private static boolean awaited(CountDownLatch latch) {
        try {
            return latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
