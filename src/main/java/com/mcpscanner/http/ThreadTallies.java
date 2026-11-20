package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class ThreadTallies implements ExchangeCounter {

    private final ThreadLocal<RequestTally> measuring = new ThreadLocal<>();

    public void record() {
        Optional.ofNullable(measuring.get()).ifPresent(RequestTally::record);
    }

    @Override
    public HttpRequestResponse counted(HttpRequestResponse exchange) {
        record();
        return exchange;
    }

    public <T> T measure(String operation, Consumer<String> summary, Supplier<T> work) {
        RequestTally outer = measuring.get();
        RequestTally tally = RequestTally.started();
        measuring.set(tally);
        try {
            return work.get();
        } finally {
            restore(outer);
            summary.accept(tally.summary(operation));
        }
    }

    public Executor carrying(Executor executor) {
        return task -> {
            RequestTally handedOver = measuring.get();
            executor.execute(() -> within(handedOver, task));
        };
    }

    private void within(RequestTally handedOver, Runnable task) {
        RequestTally outer = measuring.get();
        measuring.set(handedOver);
        try {
            task.run();
        } finally {
            restore(outer);
        }
    }

    private void restore(RequestTally outer) {
        if (outer == null) {
            measuring.remove();
        } else {
            measuring.set(outer);
        }
    }
}
