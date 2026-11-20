package com.mcpscanner.access;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class IdentityWorkers implements AutoCloseable {

    private final ExecutorService pool = Executors.newCachedThreadPool(IdentityWorkers::daemon);

    Executor executor() {
        return pool;
    }

    @Override
    public void close() {
        pool.shutdownNow();
    }

    private static Thread daemon(Runnable runnable) {
        Thread thread = new Thread(runnable, "mcp-check-access-identity");
        thread.setDaemon(true);
        return thread;
    }
}
