package com.mcpscanner.identity.discovery;

import java.time.Duration;
import java.util.function.Predicate;

public final class SettledListings {

    private final IdentityListings listings;
    private final Duration timeout;
    private final Object changed = new Object();

    public SettledListings(IdentityListings listings, Duration timeout) {
        this.listings = listings;
        this.timeout = timeout;
    }

    public void await() {
        await(identityId -> true);
    }

    public void await(Predicate<String> identityIds) {
        Runnable signal = this::signalChange;
        listings.addListener(signal);
        try {
            awaitNoneDiscovering(identityIds, System.nanoTime() + timeout.toNanos());
        } finally {
            listings.removeListener(signal);
        }
    }

    private void awaitNoneDiscovering(Predicate<String> identityIds, long deadline) {
        synchronized (changed) {
            while (anyDiscovering(identityIds)) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new IllegalStateException("Identity discovery did not finish within " + timeout);
                }
                waitForChange(remaining);
            }
        }
    }

    private void waitForChange(long nanos) {
        try {
            Duration remaining = Duration.ofNanos(nanos);
            changed.wait(Math.max(1, remaining.toMillis()));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for identity discovery", interrupted);
        }
    }

    private boolean anyDiscovering(Predicate<String> identityIds) {
        return listings.outcomes().entrySet().stream().filter(entry -> identityIds.test(entry.getKey()))
                .anyMatch(entry -> entry.getValue() instanceof DiscoveryOutcome.Discovering);
    }

    private void signalChange() {
        synchronized (changed) {
            changed.notifyAll();
        }
    }
}
