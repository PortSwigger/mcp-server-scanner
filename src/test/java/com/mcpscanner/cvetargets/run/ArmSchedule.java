package com.mcpscanner.cvetargets.run;

import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public final class ArmSchedule implements AutoCloseable {

    private static final ThreadLocal<ArmSchedule> SLOT_HELD_FROM = new ThreadLocal<>();

    private final int parallelArms;
    private final ExecutorService threads;
    private final Queue<Runnable> queued = new ArrayDeque<>();
    private int armsInSlots;
    private int armsResuming;
    private boolean closed;

    public ArmSchedule(int parallelArms) {
        if (parallelArms < 1) {
            throw new IllegalArgumentException("CVE target runs need at least one parallel arm, got " + parallelArms);
        }
        this.parallelArms = parallelArms;
        AtomicInteger names = new AtomicInteger();
        threads = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "cve-target-schedule-" + names.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    public static void waitOutsideItsSlot(Runnable wait) {
        ArmSchedule schedule = SLOT_HELD_FROM.get();
        if (schedule == null) {
            wait.run();
            return;
        }
        schedule.releaseSlot();
        try {
            wait.run();
        } finally {
            schedule.retakeSlot();
        }
    }

    public <T> CompletableFuture<T> submit(Supplier<T> arm) {
        CompletableFuture<T> result = new CompletableFuture<>();
        enqueue(() -> complete(result, arm));
        return result;
    }

    @Override
    public synchronized void close() {
        closed = true;
        queued.clear();
        threads.shutdownNow();
    }

    synchronized boolean hasAnArmResuming() {
        return armsResuming > 0;
    }

    private synchronized void enqueue(Runnable arm) {
        if (closed) {
            throw new IllegalStateException("the CVE target arm schedule is closed");
        }
        queued.add(arm);
        startQueuedArms();
    }

    private void startQueuedArms() {
        while (!closed && armsInSlots < parallelArms && armsResuming == 0 && !queued.isEmpty()) {
            armsInSlots++;
            threads.submit(holdingASlot(queued.poll()));
        }
    }

    private Runnable holdingASlot(Runnable arm) {
        return () -> {
            SLOT_HELD_FROM.set(this);
            try {
                arm.run();
            } finally {
                SLOT_HELD_FROM.remove();
                releaseSlot();
            }
        };
    }

    private synchronized void releaseSlot() {
        armsInSlots--;
        notifyAll();
        startQueuedArms();
    }

    private synchronized void retakeSlot() {
        armsResuming++;
        boolean interrupted = false;
        while (armsInSlots >= parallelArms) {
            try {
                wait();
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        armsInSlots++;
        armsResuming--;
        startQueuedArms();
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static <T> void complete(CompletableFuture<T> result, Supplier<T> arm) {
        try {
            result.complete(arm.get());
        } catch (Throwable failure) {
            result.completeExceptionally(failure);
        }
    }
}
