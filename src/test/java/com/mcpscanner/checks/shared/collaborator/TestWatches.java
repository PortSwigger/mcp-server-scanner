package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorClient;
import com.mcpscanner.http.TempFileCopies;
import com.mcpscanner.logging.McpEventLog;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public final class TestWatches {

    private static final InteractionWindow IMMEDIATE = new InteractionWindow(Duration.ZERO, Duration.ofMillis(1));

    private TestWatches() {
    }

    public static CollaboratorWatch immediate(Supplier<Optional<CollaboratorClient>> clients) {
        return new CollaboratorWatch(clients, McpEventLog.noop(), new ManualTicker(),
                new WatchTiming(new SteppingClock(), duration -> { }, IMMEDIATE));
    }

    public static CollaboratorWatch keepingIn(Supplier<Optional<CollaboratorClient>> clients, TempFileCopies copies) {
        return new CollaboratorWatch(clients, McpEventLog.noop(), new ManualTicker(),
                new WatchTiming(new SteppingClock(), duration -> { }, IMMEDIATE), copies);
    }

    public static CollaboratorWatch immediate(CollaboratorClient client) {
        return immediate(() -> Optional.of(client));
    }

    private static final class SteppingClock extends Clock {

        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.now());

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.updateAndGet(current -> current.plus(IMMEDIATE.pollInterval()));
        }
    }
}
