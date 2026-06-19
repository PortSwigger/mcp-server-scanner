package com.mcpscanner.logging;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import burp.api.montoya.logging.Logging;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

class McpEventLogTest {
    @Test
    void noopReturnsSameSingleton() {
        assertThat(McpEventLog.noop()).isSameAs(McpEventLog.noop());
    }

    @Test
    void noopMethodsAreNoOp() {
        McpEventLog noop = McpEventLog.noop();
        noop.info("should not throw");
        noop.warn("should not throw");
        noop.error("should not throw");
        noop.error("should not throw", new RuntimeException());
        assertThat(noop.snapshot()).isEmpty();
    }

    @Test
    void appendsEntryAndNotifiesListeners() {
        McpEventLog log = new McpEventLog(null);
        List<McpEventLog.LogEntry> received = new CopyOnWriteArrayList<>();
        log.addListener(received::add);

        log.info("hello");

        await().atMost(2, SECONDS)
                .pollInterval(10, MILLISECONDS)
                .untilAsserted(() -> assertThat(received).hasSize(1));
        assertThat(log.snapshot()).hasSize(1);
        assertThat(log.snapshot().get(0).message()).isEqualTo("hello");
        assertThat(log.snapshot().get(0).level()).isEqualTo(McpEventLog.Level.INFO);
    }

    @Test
    void cappedAtMaxLines() {
        McpEventLog log = new McpEventLog(null);
        for (int i = 0; i < 1100; i++) log.info("line " + i);
        assertThat(log.snapshot()).hasSize(1000);
        assertThat(log.snapshot().get(0).message()).isEqualTo("line 100");
        assertThat(log.snapshot().get(999).message()).isEqualTo("line 1099");
    }

    @Test
    void errorMirrorsToBurpLogging() {
        Logging logging = mock(Logging.class);
        McpEventLog log = new McpEventLog(logging);
        log.error("boom");
        verify(logging).logToError("boom");
    }

    @Test
    void errorWithThrowableForwardsTraceToBurpLogging() {
        Logging logging = mock(Logging.class);
        McpEventLog log = new McpEventLog(logging);
        RuntimeException ex = new RuntimeException("boom");
        log.error("oops", ex);
        verify(logging).logToError("oops", ex);
    }

    @Test
    void subscribeReturnsExistingEntriesAndReceivesSubsequentAppends() {
        McpEventLog log = new McpEventLog(null);
        log.info("first");
        log.info("second");

        List<McpEventLog.LogEntry> received = new CopyOnWriteArrayList<>();
        List<McpEventLog.LogEntry> initial = log.subscribe(received::add);

        assertThat(initial).hasSize(2);
        assertThat(initial.get(0).message()).isEqualTo("first");
        assertThat(initial.get(1).message()).isEqualTo("second");

        log.info("third");

        await().atMost(2, SECONDS)
                .pollInterval(10, MILLISECONDS)
                .untilAsserted(() -> assertThat(received).hasSize(1));
        assertThat(received.get(0).message()).isEqualTo("third");
    }

    @Test
    void lateRunningFanoutDoesNotDeliverPreSubscriptionEntries() {
        ManualExecutor executor = new ManualExecutor();
        McpEventLog log = new McpEventLog(null, executor);

        log.info("first");
        log.info("second");

        List<McpEventLog.LogEntry> received = new CopyOnWriteArrayList<>();
        log.subscribe(received::add);

        log.info("third");

        executor.drain();

        assertThat(received).hasSize(1);
        assertThat(received.get(0).message()).isEqualTo("third");
    }

    @Test
    void throwingListenerDoesNotStopOthersAndIsReportedToBurp() {
        Logging logging = mock(Logging.class);
        ManualExecutor executor = new ManualExecutor();
        McpEventLog log = new McpEventLog(logging, executor);

        RuntimeException boom = new RuntimeException("listener boom");
        log.addListener(e -> { throw boom; });
        List<McpEventLog.LogEntry> received = new CopyOnWriteArrayList<>();
        log.addListener(received::add);

        log.info("hello");
        executor.drain();

        assertThat(received).hasSize(1);
        assertThat(received.get(0).message()).isEqualTo("hello");
        verify(logging).logToError(any(String.class), eq(boom));
    }

    @Test
    void shutdownIsIdempotentAndStopsDelivery() {
        ManualExecutor executor = new ManualExecutor();
        McpEventLog log = new McpEventLog(null, executor);
        List<McpEventLog.LogEntry> received = new CopyOnWriteArrayList<>();
        log.addListener(received::add);

        log.shutdown();
        log.shutdown();

        assertThat(executor.isShutdown()).isTrue();

        log.info("after shutdown");
        executor.drain();
        assertThat(received).isEmpty();
    }

    @Test
    void appendAfterShutdownDoesNotThrowAndDeliversNothing() {
        Logging logging = mock(Logging.class);
        McpEventLog log = new McpEventLog(logging);
        List<McpEventLog.LogEntry> received = new CopyOnWriteArrayList<>();
        log.subscribe(received::add);

        log.shutdown();

        assertThatCode(() -> {
            log.info("after");
            log.warn("after");
            log.error("after");
        }).doesNotThrowAnyException();
        assertThat(received).isEmpty();
    }

    @Test
    void listenerObservationOrderMatchesAppendOrderAcrossThreads() throws Exception {
        McpEventLog log = new McpEventLog(null);
        List<String> observed = new CopyOnWriteArrayList<>();
        log.addListener(e -> observed.add(e.message()));

        int producers = 4;
        int perProducer = 250;
        Thread[] threads = new Thread[producers];
        for (int p = 0; p < producers; p++) {
            final int pid = p;
            threads[p] = new Thread(() -> {
                for (int i = 0; i < perProducer; i++) log.info("p" + pid + "-" + i);
            });
        }
        for (Thread t : threads) t.start();
        for (Thread t : threads) t.join();

        await().atMost(5, SECONDS)
                .pollInterval(20, MILLISECONDS)
                .untilAsserted(() -> assertThat(observed).hasSize(producers * perProducer));

        List<String> snapshotMessages = log.snapshot().stream()
                .map(McpEventLog.LogEntry::message).toList();
        assertThat(observed).isEqualTo(snapshotMessages);
    }

    /** Queues submitted tasks and runs them only when {@link #drain()} is called. */
    private static final class ManualExecutor extends java.util.concurrent.AbstractExecutorService {
        private final Deque<Runnable> queue = new ArrayDeque<>();
        private boolean shutdown;

        @Override public synchronized void execute(Runnable command) {
            if (!shutdown) queue.addLast(command);
        }

        void drain() {
            List<Runnable> tasks;
            synchronized (this) {
                tasks = List.copyOf(queue);
                queue.clear();
            }
            tasks.forEach(Runnable::run);
        }

        @Override public synchronized void shutdown() { shutdown = true; }

        @Override public synchronized List<Runnable> shutdownNow() {
            shutdown = true;
            List<Runnable> remaining = List.copyOf(queue);
            queue.clear();
            return remaining;
        }

        @Override public synchronized boolean isShutdown() { return shutdown; }

        @Override public synchronized boolean isTerminated() { return shutdown && queue.isEmpty(); }

        @Override public boolean awaitTermination(long timeout, java.util.concurrent.TimeUnit unit) {
            return true;
        }
    }
}
