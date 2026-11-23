package com.mcpscanner;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class DaemonWorkers {

    private DaemonWorkers() {
    }

    static ExecutorService single(String name) {
        return Executors.newSingleThreadExecutor(runnable -> daemonThread(runnable, name));
    }

    private static Thread daemonThread(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        return thread;
    }
}
