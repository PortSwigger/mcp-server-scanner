package com.mcpscanner.checks.shared.collaborator;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.scancontext.CurrentInvocation;
import com.mcpscanner.checks.shared.scancontext.CurrentScan;
import com.mcpscanner.http.TempFileCopies;
import com.mcpscanner.logging.McpEventLog;

import java.net.Inet4Address;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class CollaboratorWatch {

    public static final Duration PENDING_LIFETIME = Duration.ofMinutes(15);
    public static final int MAX_PENDING = 10_000;
    private static final int SETTLE_GRACE_POLLS = 3;
    private static final Duration SHORTEST_PAUSE = Duration.ofMillis(1);

    private final CollaboratorInteractions interactions;
    private final McpEventLog eventLog;
    private final WatchTicker ticker;
    private final WatchTiming timing;
    private final TempFileCopies copies;
    private final CollaboratorServerAddress serverAddress = new CollaboratorServerAddress();
    private final List<WatchedProbe> watched = new ArrayList<>();
    private final Object tickLock = new Object();
    private boolean ticking;
    private boolean stopped;

    public CollaboratorWatch(Supplier<Optional<CollaboratorClient>> clients, McpEventLog eventLog) {
        this(clients, eventLog, TempFileCopies.IN_MEMORY);
    }

    public CollaboratorWatch(Supplier<Optional<CollaboratorClient>> clients, McpEventLog eventLog,
                             TempFileCopies copies) {
        this(clients, eventLog, WatchTicker.scheduled(), WatchTiming.standard(), copies);
    }

    public CollaboratorWatch(Supplier<Optional<CollaboratorClient>> clients, McpEventLog eventLog,
                             WatchTicker ticker, WatchTiming timing) {
        this(clients, eventLog, ticker, timing, TempFileCopies.IN_MEMORY);
    }

    public CollaboratorWatch(Supplier<Optional<CollaboratorClient>> clients, McpEventLog eventLog,
                             WatchTicker ticker, WatchTiming timing, TempFileCopies copies) {
        this.interactions = new CollaboratorInteractions(clients, () -> timing.clock().millis() * 1_000_000L);
        this.eventLog = eventLog;
        this.ticker = ticker;
        this.timing = timing;
        this.copies = copies;
    }

    public boolean available() {
        return interactions.available();
    }

    public Optional<Inet4Address> serverIpv4() {
        return serverAddress.ipv4(interactions.server());
    }

    public HttpRequestResponse kept(HttpRequestResponse exchange) {
        return copies.kept(exchange);
    }

    public <T> T probing(CollaboratorProbes<T> probes) {
        return interactions.probing(probes);
    }

    public void watch(Collection<CollaboratorPayload> payloads, InteractionListener listener) {
        if (payloads.isEmpty()) {
            return;
        }
        Instant now = timing.clock().instant();
        if (register(new WatchedProbe(payloads, listener, CurrentScan.get(), now.plus(window().settle()),
                now.plus(PENDING_LIFETIME),
                CurrentInvocation.retainingBeyondInvocation()))) {
            startTicking();
        }
    }

    public synchronized int watchedCount() {
        return watched.size();
    }

    public synchronized int watchedCount(long scanId) {
        return (int) watched.stream().filter(probe -> probe.sentByScan(scanId)).count();
    }

    public synchronized boolean settled() {
        return watched.stream().allMatch(WatchedProbe::settled);
    }

    public void awaitSettled() {
        InteractionWindow window = window();
        Instant deadline = timing.clock().instant().plus(window.settle())
                .plus(window.pollInterval().multipliedBy(SETTLE_GRACE_POLLS));
        tick();
        while (!settled() && timing.clock().instant().isBefore(deadline)
                && !Thread.currentThread().isInterrupted()) {
            timing.pause().pause(untilNextPollOrDeadline(window, deadline));
            tick();
        }
    }

    private Duration untilNextPollOrDeadline(InteractionWindow window, Instant deadline) {
        Duration untilPoll = interactions.untilPollDue(window.pollInterval());
        Duration untilDeadline = Duration.between(timing.clock().instant(), deadline);
        Duration wait = untilPoll.compareTo(untilDeadline) < 0 ? untilPoll : untilDeadline;
        return wait.compareTo(SHORTEST_PAUSE) < 0 ? SHORTEST_PAUSE : wait;
    }

    public void shutdown() {
        synchronized (this) {
            stopped = true;
        }
        ticker.stop();
    }

    void tick() {
        synchronized (tickLock) {
            Instant polledAt = timing.clock().instant();
            if (watchedCount() > 0 && interactions.pollIfDue(window().pollInterval())) {
                markSettledBy(polledAt);
            }
            current().forEach(this::deliverNews);
            expire(timing.clock().instant());
        }
    }

    private void tickSurvivingFailure() {
        try {
            tick();
        } catch (RuntimeException failure) {
            eventLog.error("Collaborator watch: polling failed; still watching: " + failure, failure);
        }
    }

    private synchronized boolean register(WatchedProbe probe) {
        if (stopped) {
            interactions.forget(probe.payloads());
            probe.release();
            return false;
        }
        if (watched.size() >= MAX_PENDING) {
            discard(watched.get(0));
        }
        watched.add(probe);
        return true;
    }

    private void startTicking() {
        synchronized (this) {
            if (ticking || stopped) {
                return;
            }
            ticking = true;
        }
        ticker.start(this::tickSurvivingFailure, window().pollInterval());
    }

    private synchronized List<WatchedProbe> current() {
        return List.copyOf(watched);
    }

    private synchronized void markSettledBy(Instant polledAt) {
        watched.forEach(probe -> probe.settleIfPolledAfterWindow(polledAt));
    }

    private void deliverNews(WatchedProbe probe) {
        ObservedInteractions soFar = interactions.received(probe.payloads());
        if (probe.hasNews(soFar) && notify(probe, soFar) == WatchDecision.DONE) {
            synchronized (this) {
                discard(probe);
            }
        }
    }

    private WatchDecision notify(WatchedProbe probe, ObservedInteractions soFar) {
        try {
            return probe.deliver(soFar);
        } catch (RuntimeException failure) {
            eventLog.warn("Collaborator watch: reporting an interaction failed: "
                    + failure.getClass().getSimpleName() + ": " + failure.getMessage());
            return WatchDecision.DONE;
        }
    }

    private synchronized void expire(Instant now) {
        List.copyOf(watched).stream().filter(probe -> probe.expiredAt(now)).forEach(this::discard);
    }

    private void discard(WatchedProbe probe) {
        watched.remove(probe);
        interactions.forget(probe.payloads());
        probe.release();
    }

    private InteractionWindow window() {
        return interactions.declaredWindow().orElse(timing.defaultWindow());
    }
}
