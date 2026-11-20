package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.AwaitedTasks;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Function;

final class PrincipalFanOut {

    private final Executor executor;

    PrincipalFanOut(Executor executor) {
        this.executor = executor;
    }

    static PrincipalFanOut inTurn() {
        return new PrincipalFanOut(Runnable::run);
    }

    <T> Map<Principal, T> each(List<Principal> principals, Function<Principal, T> work) {
        Map<Principal, CompletableFuture<T>> started = new LinkedHashMap<>();
        for (Principal principal : principals) {
            if (AwaitedTasks.anyFailed(started.values())) {
                break;
            }
            started.put(principal, CompletableFuture.supplyAsync(() -> work.apply(principal), executor));
        }
        AwaitedTasks.awaitAll(started.values());
        Map<Principal, T> results = new LinkedHashMap<>();
        started.forEach((principal, result) -> results.put(principal, AwaitedTasks.joined(result)));
        return results;
    }
}
