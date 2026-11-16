package com.mcpscanner.access;

import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

final class ParallelItems {

    static final int PARALLELISM = 4;

    private ParallelItems() {
    }

    static <T, R> void run(List<T> items, Function<T, R> work, BiConsumer<T, R> completed,
                           BooleanSupplier continuing) {
        run(items, PARALLELISM, work, completed, continuing);
    }

    static <T, R> void run(List<T> items, int parallelism, Function<T, R> work, BiConsumer<T, R> completed,
                           BooleanSupplier continuing) {
        ExecutorService pool = Executors.newFixedThreadPool(parallelism, ParallelItems::daemon);
        try {
            drain(items.iterator(), parallelism, new ExecutorCompletionService<>(pool), work, completed, continuing);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }
    }

    private static <T, R> void drain(Iterator<T> pending, int parallelism, CompletionService<Completed<T, R>> completions,
                                     Function<T, R> work, BiConsumer<T, R> completed, BooleanSupplier continuing)
            throws InterruptedException {
        int inFlight = 0;
        while (true) {
            while (inFlight < parallelism && pending.hasNext() && continuing.getAsBoolean()) {
                T item = pending.next();
                completions.submit(() -> new Completed<>(item, work.apply(item)));
                inFlight++;
            }
            if (inFlight == 0) {
                return;
            }
            Completed<T, R> done = resultOf(completions);
            inFlight--;
            completed.accept(done.item(), done.result());
        }
    }

    private static <T, R> Completed<T, R> resultOf(CompletionService<Completed<T, R>> completions)
            throws InterruptedException {
        try {
            return completions.take().get();
        } catch (ExecutionException failure) {
            throw new IllegalStateException(failure.getCause());
        }
    }

    private static Thread daemon(Runnable runnable) {
        Thread thread = new Thread(runnable, "mcp-check-access-item");
        thread.setDaemon(true);
        return thread;
    }

    private record Completed<T, R>(T item, R result) {
    }
}
