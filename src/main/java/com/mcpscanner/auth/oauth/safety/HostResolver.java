package com.mcpscanner.auth.oauth.safety;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Resolves hostnames to IP addresses with a bounded timeout. Injectable so tests can stub
 * resolution deterministically without hitting real DNS.
 */
public interface HostResolver {

    /**
     * @return the resolved addresses, or an empty list if resolution failed (unknown host).
     * @throws ResolutionTimeoutException when the timeout elapses before a result arrives.
     */
    List<InetAddress> resolve(String host) throws ResolutionTimeoutException;

    /** Single-attempt resolver that bounds {@link InetAddress#getAllByName(String)} with a timeout. */
    static HostResolver bounded(Duration timeout) {
        return new BoundedHostResolver(timeout);
    }

    /** Convenience for the 2s default the gate uses. */
    static HostResolver defaultResolver() {
        return bounded(Duration.ofSeconds(2));
    }

    /**
     * Shuts down the shared DNS executor so the extension unloads cleanly without leaking
     * threads. Safe to call repeatedly; a subsequent resolve lazily recreates the pool, so a
     * Burp extension reload after an unload still works.
     */
    static void shutdownExecutor() {
        BoundedHostResolver.shutdownSharedExecutor();
    }

    /** Thrown when DNS resolution does not complete within the bound, or fails non-recoverably. */
    final class ResolutionTimeoutException extends Exception {
        public ResolutionTimeoutException(String message) {
            super(message);
        }

        public ResolutionTimeoutException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Lookup hook so tests can substitute the JDK call without binding to real DNS. */
    @FunctionalInterface
    interface Lookup {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    /** JDK-backed implementation; uses a shared daemon executor so callers can't leak threads. */
    final class BoundedHostResolver implements HostResolver {

        // Lazily (re)created so an extension unload can shut it down and a later reload still works.
        private static ExecutorService sharedExecutor;

        private final Duration timeout;
        private final Lookup lookup;

        private static synchronized ExecutorService sharedExecutor() {
            if (sharedExecutor == null || sharedExecutor.isShutdown()) {
                sharedExecutor = Executors.newCachedThreadPool(new DaemonThreadFactory());
            }
            return sharedExecutor;
        }

        private static synchronized void shutdownSharedExecutor() {
            if (sharedExecutor != null) {
                sharedExecutor.shutdownNow();
                sharedExecutor = null;
            }
        }

        BoundedHostResolver(Duration timeout) {
            this(timeout, InetAddress::getAllByName);
        }

        BoundedHostResolver(Duration timeout, Lookup lookup) {
            this.timeout = timeout;
            this.lookup = lookup;
        }

        @Override
        public List<InetAddress> resolve(String host) throws ResolutionTimeoutException {
            Future<InetAddress[]> future = sharedExecutor().submit(() -> lookup.resolve(host));
            try {
                return List.of(future.get(timeout.toMillis(), TimeUnit.MILLISECONDS));
            } catch (TimeoutException e) {
                future.cancel(true);
                throw new ResolutionTimeoutException(
                        "DNS resolution for " + host + " timed out after " + timeout.toMillis() + "ms");
            } catch (java.util.concurrent.ExecutionException e) {
                if (e.getCause() instanceof UnknownHostException) {
                    return List.of();
                }
                // Any other resolution failure (SecurityException, OOM during native lookup, etc.) must NOT
                // silently fall through as "no classifications" — surface as UNRESOLVABLE so the gate hard-blocks.
                Throwable cause = e.getCause();
                String causeName = cause != null ? cause.getClass().getSimpleName() : "ExecutionException";
                throw new ResolutionTimeoutException(
                        "DNS resolution for " + host + " failed: " + causeName,
                        cause != null ? cause : e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                future.cancel(true);
                throw new ResolutionTimeoutException(
                        "Interrupted while resolving " + host);
            }
        }

        private static final class DaemonThreadFactory implements ThreadFactory {
            private final AtomicInteger counter = new AtomicInteger();

            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "SuspiciousDestinationGate-dns-" + counter.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        }
    }
}
