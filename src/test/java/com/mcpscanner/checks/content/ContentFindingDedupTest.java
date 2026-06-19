package com.mcpscanner.checks.content;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ContentFindingDedupTest {

    private final ContentFindingDedup dedup = new ContentFindingDedup();

    @Test
    void firstClaimWinsAndRepeatIsRejected() {
        assertThat(dedup.tryClaim("rule", "AKIA123", "https://mcp.example.test")).isTrue();
        assertThat(dedup.tryClaim("rule", "AKIA123", "https://mcp.example.test")).isFalse();
    }

    @Test
    void differingRuleValueOrHostAreIndependentClaims() {
        assertThat(dedup.tryClaim("rule-a", "AKIA123", "https://mcp.example.test")).isTrue();
        assertThat(dedup.tryClaim("rule-b", "AKIA123", "https://mcp.example.test")).isTrue();
        assertThat(dedup.tryClaim("rule-a", "AKIA999", "https://mcp.example.test")).isTrue();
        assertThat(dedup.tryClaim("rule-a", "AKIA123", "https://other.example.test")).isTrue();
    }

    @Test
    void clearResetsClaimsSoTheSameKeyCanBeReclaimed() {
        dedup.tryClaim("rule", "AKIA123", "https://mcp.example.test");

        dedup.clear();

        assertThat(dedup.tryClaim("rule", "AKIA123", "https://mcp.example.test")).isTrue();
    }

    @Test
    void concurrentClaimsOnSameKeyYieldExactlyOneWinner() throws InterruptedException {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();
        Set<Integer> results = ConcurrentHashMap.newKeySet();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                awaitQuietly(start);
                if (dedup.tryClaim("rule", "AKIA123", "https://mcp.example.test")) {
                    winners.incrementAndGet();
                }
                results.add(1);
            });
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        assertThat(winners.get()).isEqualTo(1);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
