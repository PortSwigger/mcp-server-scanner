package com.mcpscanner.client;

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class LiveSessionProbe {

    private static final Duration MARGIN_OVER_TRANSPORT_TIMEOUT = Duration.ofSeconds(5);

    public static final Duration DEFAULT_TIMEOUT =
            McpScannerSession.DEFAULT_REQUEST_TIMEOUT.plus(MARGIN_OVER_TRANSPORT_TIMEOUT);

    private final Runnable ping;
    private final Duration timeout;

    public LiveSessionProbe(Runnable ping, Duration timeout) {
        this.ping = ping;
        this.timeout = timeout;
    }

    public PingOutcome ping() {
        ExecutorService pinger = Executors.newSingleThreadExecutor(LiveSessionProbe::daemonThread);
        try {
            Future<?> pinging = pinger.submit(ping);
            return await(pinging);
        } finally {
            pinger.shutdownNow();
        }
    }

    private PingOutcome await(Future<?> pinging) {
        try {
            pinging.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            return PingOutcome.ANSWERED;
        } catch (TimeoutException unanswered) {
            pinging.cancel(true);
            return PingOutcome.TIMED_OUT;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return PingOutcome.INCONCLUSIVE;
        } catch (ExecutionException failed) {
            return PingFailureClassifier.classify(failed.getCause());
        }
    }

    private static Thread daemonThread(Runnable task) {
        Thread thread = new Thread(task, "live-session-ping");
        thread.setDaemon(true);
        return thread;
    }
}
