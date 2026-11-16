package com.mcpscanner.checks.shared.scancontext;

import com.mcpscanner.http.ExchangeLease;
import com.mcpscanner.http.ExchangeRetention;

import java.util.Optional;
import java.util.function.Supplier;

public final class CurrentInvocation {

    private static final ThreadLocal<ExchangeLease> LEASE = new ThreadLocal<>();

    private CurrentInvocation() {
    }

    @FunctionalInterface
    public interface Retention {

        void release();
    }

    public static Retention retainingBeyondInvocation() {
        ExchangeRetention retained = Optional.ofNullable(LEASE.get()).map(ExchangeLease::retainBeyondClose)
                .orElse(ExchangeRetention.NONE);
        return retained::release;
    }

    public static <T> T holding(ExchangeLease lease, Supplier<T> work) {
        ExchangeLease previous = LEASE.get();
        LEASE.set(lease);
        try {
            return work.get();
        } finally {
            if (previous == null) {
                LEASE.remove();
            } else {
                LEASE.set(previous);
            }
        }
    }
}
