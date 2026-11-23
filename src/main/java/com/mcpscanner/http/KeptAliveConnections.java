package com.mcpscanner.http;

import burp.api.montoya.http.HttpService;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

final class KeptAliveConnections {

    static final Duration IDLE_LIMIT = Duration.ofSeconds(1);
    static final int MAX_CONNECTIONS_PER_ORIGIN = 64;

    private final Clock clock;
    private final AtomicLong opened = new AtomicLong();
    private final AtomicLong generation = new AtomicLong();
    private final ConcurrentMap<String, OriginPool> poolByOrigin = new ConcurrentHashMap<>();

    KeptAliveConnections(Clock clock) {
        this.clock = clock;
    }

    Optional<Lease> take(SendPath path, HttpService service) {
        long takenIn = generation.get();
        String origin = OriginConnections.originOf(service);
        OriginPool pool = poolOf(origin);
        synchronized (pool) {
            Deque<IdleConnection> idle = pool.idleOn(path);
            IdleConnection newest = idle.pollFirst();
            if (newest != null && newest.freshAt(clock.instant())) {
                return Optional.of(new Lease(newest.connectionId(), takenIn));
            }
            idle.clear();
            if (pool.opened == MAX_CONNECTIONS_PER_ORIGIN) {
                return Optional.empty();
            }
            pool.opened++;
        }
        return Optional.of(new Lease(ConnectionReuse.CONNECTION_ID + "-" + origin + "-" + opened.incrementAndGet(),
                takenIn));
    }

    void putBack(SendPath path, HttpService service, Lease lease) {
        OriginPool pool = poolOf(OriginConnections.originOf(service));
        synchronized (pool) {
            if (lease.generation() == generation.get()) {
                pool.idleOn(path).addFirst(new IdleConnection(lease.connectionId(), clock.instant()));
            }
        }
    }

    void forget() {
        generation.incrementAndGet();
        poolByOrigin.clear();
    }

    private OriginPool poolOf(String origin) {
        return poolByOrigin.computeIfAbsent(origin, key -> new OriginPool());
    }

    record Lease(String connectionId, long generation) {
    }

    private static final class OriginPool {
        private final Map<SendPath, Deque<IdleConnection>> idleByPath = new EnumMap<>(SendPath.class);
        private int opened;

        Deque<IdleConnection> idleOn(SendPath path) {
            return idleByPath.computeIfAbsent(path, unused -> new ArrayDeque<>());
        }
    }

    private record IdleConnection(String connectionId, Instant answeredAt) {

        boolean freshAt(Instant now) {
            return Duration.between(answeredAt, now).compareTo(IDLE_LIMIT) <= 0;
        }
    }
}
