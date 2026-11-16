package com.mcpscanner.checks.api.crossidentity;

import java.util.Optional;
import java.util.function.Function;

public record IssuedSession<T>(Optional<T> value, Outcome outcome) {

    public enum Outcome {
        ISSUED, NO_SESSION_ISSUED, INITIALIZE_FAILED
    }

    public static <T> IssuedSession<T> issued(T value) {
        return new IssuedSession<>(Optional.of(value), Outcome.ISSUED);
    }

    public static <T> IssuedSession<T> noSessionIssued() {
        return new IssuedSession<>(Optional.empty(), Outcome.NO_SESSION_ISSUED);
    }

    public static <T> IssuedSession<T> initializeFailed() {
        return new IssuedSession<>(Optional.empty(), Outcome.INITIALIZE_FAILED);
    }

    public <R> IssuedSession<R> map(Function<T, R> mapping) {
        return new IssuedSession<>(value.map(mapping), outcome);
    }

    public <R> IssuedSession<R> flatMap(Function<T, Optional<R>> mapping) {
        Optional<R> mapped = value.flatMap(mapping);
        return new IssuedSession<>(mapped, value.isPresent() && mapped.isEmpty() ? Outcome.NO_SESSION_ISSUED : outcome);
    }
}
