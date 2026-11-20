package com.mcpscanner.testutil;

import com.mcpscanner.ui.widgets.ReadScheduler;
import com.mcpscanner.ui.widgets.UiReads;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;

public final class ManualReadScheduler implements ReadScheduler {

    public final List<Throwable> failures = new ArrayList<>();
    private static final long READY_WITHIN_MILLIS = 500;

    private final Deque<Scheduled> pending = new ArrayDeque<>();
    private final List<Long> delays = new ArrayList<>();
    private long now;

    public static UiReads immediateReads() {
        return new UiReads(new ReadScheduler() {
            @Override
            public void schedule(Runnable task, long delayMillis) {
                task.run();
            }

            @Override
            public long nowMillis() {
                return 0;
            }

            @Override
            public void shutdown() {
            }
        }, Runnable::run, (message, failure) -> { });
    }

    public UiReads reads() {
        return new UiReads(this, Runnable::run, (message, failure) -> failures.add(failure));
    }

    @Override
    public synchronized void schedule(Runnable task, long delayMillis) {
        pending.addLast(new Scheduled(task, delayMillis));
        delays.add(delayMillis);
    }

    @Override
    public synchronized long nowMillis() {
        return now;
    }

    @Override
    public void shutdown() {
    }

    public synchronized void advance(long millis) {
        now += millis;
    }

    public void runNext() {
        Scheduled next;
        synchronized (this) {
            next = pending.removeFirst();
        }
        next.task().run();
    }

    public void runReady() {
        Optional<Scheduled> ready;
        while ((ready = takeReady()).isPresent()) {
            ready.get().task().run();
        }
    }

    private synchronized Optional<Scheduled> takeReady() {
        Optional<Scheduled> ready = pending.stream().filter(task -> task.delayMillis() <= READY_WITHIN_MILLIS)
                .findFirst();
        ready.ifPresent(pending::remove);
        return ready;
    }

    public void runAll() {
        while (pendingCount() > 0) {
            runNext();
        }
    }

    public synchronized int pendingCount() {
        return pending.size();
    }

    public synchronized long lastDelay() {
        return delays.get(delays.size() - 1);
    }

    private record Scheduled(Runnable task, long delayMillis) {
    }
}
