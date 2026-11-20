package com.mcpscanner.ui.widgets;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static com.mcpscanner.testutil.Polling.within;
import static org.assertj.core.api.Assertions.assertThat;

class DaemonReadSchedulerTest {

    @Test
    void aFeedRequestedOnTheEdtReadsOffItAndAppliesOnIt() throws Exception {
        DaemonReadScheduler scheduler = new DaemonReadScheduler();
        AtomicReference<Boolean> readOnEdt = new AtomicReference<>();
        AtomicReference<Boolean> appliedOnEdt = new AtomicReference<>();
        OffEdtFeed<String> feed = UiReads.background(scheduler, (message, failure) -> { }).feed(0, () -> {
            readOnEdt.set(SwingUtilities.isEventDispatchThread());
            return "value";
        }, value -> appliedOnEdt.set(SwingUtilities.isEventDispatchThread()));
        try {
            SwingUtilities.invokeAndWait(feed::request);

            within(Duration.ofSeconds(5)).until(() -> appliedOnEdt.get() != null);
            assertThat(readOnEdt.get()).isFalse();
            assertThat(appliedOnEdt.get()).isTrue();
        } finally {
            scheduler.shutdown();
        }
    }
}
