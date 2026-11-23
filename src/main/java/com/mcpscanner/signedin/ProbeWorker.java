package com.mcpscanner.signedin;

import com.mcpscanner.logging.McpEventLog;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

public final class ProbeWorker implements Executor {

    private static final String THREAD_NAME = "mcp-browser-consent-check";
    private static final String LOG_PREFIX = "Browser consent check: ";

    private final ExecutorService executor;
    private final McpEventLog eventLog;

    private ProbeWorker(ExecutorService executor, McpEventLog eventLog) {
        this.executor = executor;
        this.eventLog = eventLog;
    }

    public static ProbeWorker daemon(McpEventLog eventLog) {
        return new ProbeWorker(Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, THREAD_NAME);
            thread.setDaemon(true);
            return thread;
        }), eventLog);
    }

    @Override
    public void execute(Runnable probe) {
        try {
            executor.execute(() -> runLoggingFailure(probe));
        } catch (RejectedExecutionException unloading) {
            eventLog.info(LOG_PREFIX + "not run: the extension is unloading");
        }
    }

    private void runLoggingFailure(Runnable probe) {
        try {
            probe.run();
        } catch (RuntimeException failure) {
            eventLog.error(LOG_PREFIX + "failed: " + failure, failure);
        }
    }

    public void stop(Duration cleanupWait) {
        int dropped = executor.shutdownNow().size();
        if (dropped > 0) {
            eventLog.info(LOG_PREFIX + dropped + " queued probe run not run: the extension is unloading");
        }
        if (!terminatedWithin(cleanupWait)) {
            eventLog.warn(LOG_PREFIX + "still running " + cleanupWait.toSeconds() + " s after unload began; its "
                    + "probe clients may be left registered at the authorization server");
        }
    }

    private boolean terminatedWithin(Duration wait) {
        try {
            return executor.awaitTermination(wait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
