package com.mcpscanner.signedin;

import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class ProbeWorkerTest {

    private final McpEventLog log = new McpEventLog(null);
    private final CountDownLatch release = new CountDownLatch(1);

    @AfterEach
    void releaseStubbornProbes() {
        release.countDown();
    }

    @Test
    void runsProbesOnADaemonThreadOffTheCaller() throws Exception {
        CompletableFuture<Thread> ranOn = new CompletableFuture<>();

        ProbeWorker.daemon(log).execute(() -> ranOn.complete(Thread.currentThread()));

        Thread worker = ranOn.get(5, TimeUnit.SECONDS);
        assertThat(worker).isNotSameAs(Thread.currentThread());
        assertThat(worker.isDaemon()).isTrue();
    }

    @Test
    void stoppingInterruptsTheRunningProbeAndWaitsForItsCleanup() throws Exception {
        ProbeWorker worker = ProbeWorker.daemon(log);
        CompletableFuture<Thread> running = new CompletableFuture<>();
        AtomicBoolean cleanedUp = new AtomicBoolean();
        worker.execute(() -> {
            running.complete(Thread.currentThread());
            try {
                release.await();
            } catch (InterruptedException unload) {
                Thread.currentThread().interrupt();
            } finally {
                cleanedUp.set(true);
            }
        });
        Thread thread = running.get(5, TimeUnit.SECONDS);

        worker.stop(Duration.ofSeconds(5));

        assertThat(cleanedUp).isTrue();
        await().atMost(Duration.ofSeconds(5)).until(() -> !thread.isAlive());
        assertThat(messages()).noneMatch(message -> message.contains("left registered"));
    }

    @Test
    void aProbeStillRunningAfterTheWaitIsLoggedAsPossiblyLeavingItsClientsRegistered() throws Exception {
        ProbeWorker worker = ProbeWorker.daemon(log);
        CompletableFuture<Void> running = new CompletableFuture<>();
        worker.execute(() -> {
            running.complete(null);
            awaitIgnoringInterrupts(release);
        });
        running.get(5, TimeUnit.SECONDS);

        worker.stop(Duration.ofMillis(50));

        assertThat(messages()).anyMatch(message -> message.contains("left registered"));
    }

    @Test
    void aProbeStillQueuedAtUnloadIsLoggedAsNotRun() throws Exception {
        ProbeWorker worker = ProbeWorker.daemon(log);
        CompletableFuture<Void> running = new CompletableFuture<>();
        AtomicBoolean queuedRan = new AtomicBoolean();
        worker.execute(() -> {
            running.complete(null);
            try {
                release.await();
            } catch (InterruptedException unload) {
                Thread.currentThread().interrupt();
            }
        });
        worker.execute(() -> queuedRan.set(true));
        running.get(5, TimeUnit.SECONDS);

        worker.stop(Duration.ofSeconds(5));

        assertThat(queuedRan).isFalse();
        assertThat(messages()).anyMatch(message -> message.contains("1 queued probe run not run"));
    }

    @Test
    void aProbeThatThrowsIsLoggedAsAnErrorWithItsStackTrace() {
        ProbeWorker worker = ProbeWorker.daemon(log);
        IllegalStateException failure = new IllegalStateException("extension unloaded");

        worker.execute(() -> {
            throw failure;
        });

        await().atMost(Duration.ofSeconds(5)).until(() -> !log.snapshot().isEmpty());
        McpEventLog.LogEntry entry = log.snapshot().get(0);
        assertThat(entry.level()).isEqualTo(McpEventLog.Level.ERROR);
        assertThat(entry.message()).startsWith("Browser consent check: ");
        assertThat(entry.throwable()).isSameAs(failure);
    }

    @Test
    void stoppingAnIdleWorkerLogsNothing() {
        ProbeWorker worker = ProbeWorker.daemon(log);

        worker.stop(Duration.ofSeconds(5));

        assertThat(messages()).isEmpty();
    }

    @Test
    void aStoppedWorkerRunsNoFurtherProbe() {
        ProbeWorker worker = ProbeWorker.daemon(log);
        AtomicBoolean ran = new AtomicBoolean();
        worker.stop(Duration.ofSeconds(5));

        worker.execute(() -> ran.set(true));

        assertThat(ran).isFalse();
    }

    private java.util.List<String> messages() {
        return log.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }

    private static void awaitIgnoringInterrupts(CountDownLatch latch) {
        boolean interrupted = false;
        while (latch.getCount() > 0) {
            try {
                latch.await();
            } catch (InterruptedException ignored) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
