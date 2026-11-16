package com.mcpscanner.scan;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class DaemonEndPollerTest {

    @Test
    void shuttingDownStopsTheExecutor() {
        DaemonEndPoller poller = new DaemonEndPoller();

        poller.shutdown();

        assertThat(poller.isShutdown()).isTrue();
    }

    @Test
    void shuttingDownEndsTheThreadThatWaitedForTheNextPoll() {
        Set<Thread> before = pollerThreads();
        DaemonEndPoller poller = new DaemonEndPoller();
        poller.pollLater(() -> { });
        await().atMost(Duration.ofSeconds(5)).until(() -> !newPollerThreads(before).isEmpty());
        Thread waiting = newPollerThreads(before).get(0);

        poller.shutdown();

        await().atMost(Duration.ofSeconds(5)).until(() -> !waiting.isAlive());
    }

    private static Set<Thread> pollerThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> "mcp-scan-end-poller".equals(thread.getName())).collect(Collectors.toSet());
    }

    private static List<Thread> newPollerThreads(Set<Thread> before) {
        return pollerThreads().stream().filter(thread -> !before.contains(thread)).toList();
    }

    @Test
    void anIdlePollerKeepsNoThreadAlive() throws Exception {
        DaemonEndPoller poller = new DaemonEndPoller();

        assertThat(poller.allowsCoreThreadTimeOut()).isTrue();
        poller.shutdown();
    }
}
