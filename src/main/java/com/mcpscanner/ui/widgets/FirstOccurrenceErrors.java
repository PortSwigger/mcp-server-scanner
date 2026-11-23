package com.mcpscanner.ui.widgets;

import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public final class FirstOccurrenceErrors {

    private final BiConsumer<String, Throwable> error;
    private final Consumer<String> debug;
    private String lastSignature;

    public FirstOccurrenceErrors(BiConsumer<String, Throwable> error, Consumer<String> debug) {
        this.error = error;
        this.debug = debug;
    }

    public synchronized void report(String message, Throwable failure) {
        String signature = signatureOf(failure);
        if (Objects.equals(signature, lastSignature)) {
            debug.accept(message + " (again)");
            return;
        }
        lastSignature = signature;
        error.accept(message, failure);
    }

    private static String signatureOf(Throwable failure) {
        return failure.getClass().getName() + ": " + failure.getMessage();
    }
}
