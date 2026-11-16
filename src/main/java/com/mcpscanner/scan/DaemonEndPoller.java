package com.mcpscanner.scan;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

final class DaemonEndPoller implements EndPoller {

    private static final long POLL_DELAY_SECONDS = 5;
    private static final long IDLE_THREAD_SECONDS = 10;

    private final ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, task -> {
        Thread thread = new Thread(task, "mcp-scan-end-poller");
        thread.setDaemon(true);
        return thread;
    }, new ScheduledThreadPoolExecutor.DiscardPolicy());

    DaemonEndPoller() {
        executor.setKeepAliveTime(IDLE_THREAD_SECONDS, TimeUnit.SECONDS);
        executor.allowCoreThreadTimeOut(true);
    }

    @Override
    public void pollLater(Runnable poll) {
        executor.schedule(poll, POLL_DELAY_SECONDS, TimeUnit.SECONDS);
    }

    @Override
    public void shutdown() {
        executor.shutdownNow();
    }

    boolean allowsCoreThreadTimeOut() {
        return executor.allowsCoreThreadTimeOut();
    }

    boolean isShutdown() {
        return executor.isShutdown();
    }
}
