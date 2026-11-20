package com.mcpscanner.ui.widgets;

import com.mcpscanner.testutil.ManualReadScheduler;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class UiReadsTest {

    private final ManualReadScheduler scheduler = new ManualReadScheduler();
    private final List<Runnable> edt = new ArrayList<>();
    private final UiReads reads = new UiReads(scheduler, edt::add,
            (message, failure) -> scheduler.failures.add(failure));
    private final AtomicInteger computed = new AtomicInteger();
    private final List<Integer> applied = new ArrayList<>();

    @Test
    void computesOnTheSchedulerAndAppliesTheResultOnTheEdt() {
        reads.compute(computed::incrementAndGet, applied::add);

        assertThat(computed).hasValue(0);
        scheduler.runNext();
        assertThat(computed).hasValue(1);
        assertThat(applied).isEmpty();

        edt.forEach(Runnable::run);
        assertThat(applied).containsExactly(1);
    }

    @Test
    void failedWorkIsLoggedAsAnErrorWithItsStackTraceAndAppliesNothing() {
        reads.<Integer>compute(() -> {
            throw new IllegalStateException("boom");
        }, applied::add);

        scheduler.runNext();

        assertThat(edt).isEmpty();
        assertThat(scheduler.failures).singleElement().isInstanceOf(IllegalStateException.class);
    }
}
