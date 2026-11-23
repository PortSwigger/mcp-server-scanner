package com.mcpscanner.checks.api.crossidentity;

import java.util.Collection;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class AwaitedTasks {

    private AwaitedTasks() {
    }

    public static void awaitAll(Collection<? extends CompletableFuture<?>> tasks) {
        CompletableFuture.allOf(tasks.toArray(CompletableFuture[]::new)).handle((ignored, failure) -> null).join();
    }

    public static boolean anyFailed(Collection<? extends CompletableFuture<?>> tasks) {
        return tasks.stream().anyMatch(CompletableFuture::isCompletedExceptionally);
    }

    public static <T> T joined(CompletableFuture<T> task) {
        try {
            return task.join();
        } catch (CompletionException failure) {
            throw unwrapped(failure.getCause());
        }
    }

    private static RuntimeException unwrapped(Throwable cause) {
        if (cause instanceof Error error) {
            throw error;
        }
        return cause instanceof RuntimeException runtime ? runtime : new IllegalStateException(cause);
    }
}
