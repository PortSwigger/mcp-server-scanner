package com.mcpscanner.http;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

class ThreadTalliesTest {

    private final ThreadTallies tallies = new ThreadTallies();
    private final List<String> summaries = new ArrayList<>();

    @Test
    void countsOnlyTheMeasuringThreadsRequests() {
        tallies.record();

        tallies.measure("Item", summaries::add, () -> {
            tallies.record();
            CompletableFuture.runAsync(tallies::record).join();
            return null;
        });

        assertThat(summaries).singleElement().asString().startsWith("Item: 1 request, ");
    }

    @Test
    void anInnerMeasurementLeavesTheOuterOneCounting() {
        tallies.measure("Outer", summaries::add, () -> {
            tallies.measure("Inner", summaries::add, () -> {
                tallies.record();
                return null;
            });
            tallies.record();
            return null;
        });

        assertThat(summaries).extracting(summary -> summary.substring(0, summary.indexOf(',')))
                .containsExactly("Inner: 1 request", "Outer: 1 request");
    }

    @Test
    void workHandedToACarryingExecutorCountsTowardsTheMeasurementThatHandedItOver() {
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            tallies.measure("Item", summaries::add, () ->
                    CompletableFuture.runAsync(tallies::record, tallies.carrying(pool)).join());
        } finally {
            pool.shutdownNow();
        }

        assertThat(summaries).singleElement().asString().startsWith("Item: 1 request, ");
    }
}
