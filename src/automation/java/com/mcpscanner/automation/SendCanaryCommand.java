package com.mcpscanner.automation;

import java.time.Duration;

public record SendCanaryCommand(String url, int count, int concurrency, int queueWaitMillis) {

    public static final int MAX_COUNT = 10_000;
    public static final int MAX_CONCURRENCY = 64;
    public static final int MAX_QUEUE_WAIT_MILLIS = 60_000;

    public SendCanaryCommand {
        WebUrls.requireWeb(url);
        requireWithin("count", count, 1, MAX_COUNT);
        requireWithin("concurrency", concurrency, 1, MAX_CONCURRENCY);
        requireWithin("queueWaitMillis", queueWaitMillis, 0, MAX_QUEUE_WAIT_MILLIS);
    }

    public SendCanaryCommand(String url, int count, int concurrency) {
        this(url, count, concurrency, 0);
    }

    Duration queueWait() {
        return Duration.ofMillis(queueWaitMillis);
    }

    boolean queued() {
        return queueWaitMillis > 0;
    }

    private static void requireWithin(String name, int value, int min, int max) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(name + " must be " + min + ".." + max + ", got " + value);
        }
    }
}
